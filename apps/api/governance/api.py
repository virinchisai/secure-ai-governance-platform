from __future__ import annotations

from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from .agent import AgentSecurityError
from .approvals import ApprovalError
from .domain import (
    AgentResponse,
    ApprovalRecord,
    AuditEvent,
    ClassificationResult,
    RiskAssessment,
    Role,
    UserContext,
)
from .identity import AuthenticationError, TokenService
from .rbac import AuthorizationError
from .runtime import Runtime
from .schemas import (
    ApprovalDecisionRequest,
    ApprovalExecutionRequest,
    ClassificationRequest,
    KnowledgeSearchRequest,
    LoginRequest,
    SafeQueryRequest,
    SummaryEmailRequest,
    TokenResponse,
)

router = APIRouter(prefix="/api")


def runtime(request: Request) -> Runtime:
    return cast(Runtime, request.app.state.runtime)


def current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> UserContext:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    try:
        services = cast(Runtime, request.app.state.runtime)
        return services.tokens.verify(authorization[7:])
    except AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, services: Annotated[Runtime, Depends(runtime)]) -> TokenResponse:
    if not isinstance(services.tokens, TokenService):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Local password login is disabled; use the configured OIDC authorization flow",
        )
    try:
        context = services.identity.authenticate(body.username, body.password)
    except AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return TokenResponse(access_token=services.tokens.issue(context))


@router.get("/me")
def me(context: Annotated[UserContext, Depends(current_user)]) -> UserContext:
    return context


@router.get("/documents")
def list_documents(
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> list[dict[str, str]]:
    services.authorizer.authorize_tool(context, "list_files")
    return [
        {"document_id": item.document_id, "name": item.name, "workspace_id": item.workspace_id}
        for item in services.graph.list_files(context.workspace_id)
    ]


@router.get("/documents/{document_id}")
def get_document(
    document_id: str,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> dict[str, object]:
    services.authorizer.authorize_tool(context, "get_document")
    try:
        document = services.graph.read_file(context.workspace_id, document_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Document not found") from exc
    classification = services.classifier.classify(document.content)
    return {"document": document, "classification": classification}


@router.post("/classify")
def classify(
    body: ClassificationRequest,
    _context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> ClassificationResult:
    return services.classifier.classify(body.content)


@router.post("/knowledge/search")
def search_knowledge(
    body: KnowledgeSearchRequest,
    request: Request,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> list[dict[str, object]]:
    services.authorizer.authorize_tool(context, "search_documents")
    chunks = services.knowledge.search(context.workspace_id, body.query, body.limit)
    for _chunk in chunks:
        services.risk.record(context.user_id, "document_access")
    services.audit.emit(
        AuditEvent(
            request_id=request.state.request_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action="knowledge.search",
            tool="search_documents",
            resource=f"result_count:{len(chunks)}",
            result="allowed",
            risk_score=services.risk.assess(context.user_id).score,
            reason="Workspace-filtered knowledge search completed",
            event_type="document_search",
        )
    )
    return [chunk.model_dump() for chunk in chunks]


@router.post("/agent/summarize-email")
def summarize_email(
    body: SummaryEmailRequest,
    request: Request,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> AgentResponse:
    try:
        return services.agent.summarize_and_email(
            context=context,
            document_ids=body.document_ids,
            recipient=body.recipient,
            request_id=request.state.request_id,
        )
    except (AgentSecurityError, AuthorizationError) as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc


@router.get("/approvals")
def approvals(
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> list[ApprovalRecord]:
    return services.approvals.list_for_workspace(context.workspace_id)


@router.post("/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str,
    body: ApprovalDecisionRequest,
    request: Request,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> ApprovalRecord:
    if not context.roles.intersection({Role.COMPLIANCE_ADMIN, Role.SECURITY_ADMIN}):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Compliance or security administrator role required"
        )
    try:
        approval = services.approvals.get(approval_id)
        if approval.workspace_id != context.workspace_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
        decided = services.approvals.decide(
            approval_id, approver_id=context.user_id, approve=body.approve
        )
        services.audit.emit(
            AuditEvent(
                request_id=request.state.request_id,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                action="approval.decide",
                tool=None,
                resource=approval_id,
                approval_id=approval_id,
                result="approved" if body.approve else "denied",
                risk_score=services.risk.assess(context.user_id).score,
                reason="Authorized administrator decision",
                event_type="approval_granted" if body.approve else "approval_denied",
            )
        )
        return decided
    except ApprovalError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.post("/approvals/{approval_id}/execute")
def execute_approval(
    approval_id: str,
    body: ApprovalExecutionRequest,
    request: Request,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> AgentResponse:
    try:
        return services.agent.execute_approved_email(
            context=context,
            approval_id=approval_id,
            arguments=body.arguments,
            request_id=request.state.request_id,
        )
    except (ApprovalError, AgentSecurityError, AuthorizationError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.get("/audit")
def audit_events(
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> list[AuditEvent]:
    return services.audit.list_events(context.workspace_id)


@router.get("/risk")
def risk_dashboard(
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> RiskAssessment:
    return services.risk.assess(context.user_id)


@router.get("/policies")
def policies(_context: Annotated[UserContext, Depends(current_user)]) -> list[dict[str, str]]:
    return [
        {
            "policy_id": "DLP-SECRET-001",
            "effect": "BLOCK",
            "description": "Block secrets in output",
        },
        {
            "policy_id": "DLP-EXT-001",
            "effect": "BLOCK",
            "description": "Block highly confidential external sharing",
        },
        {
            "policy_id": "DLP-EXT-002",
            "effect": "REQUIRE_APPROVAL",
            "description": "Approve confidential external sharing",
        },
        {"policy_id": "DLP-PII-001", "effect": "REDACT", "description": "Redact high-risk PII"},
        {
            "policy_id": "DLP-INTERNAL-001",
            "effect": "ALLOW",
            "description": "Allow authorized internal sharing",
        },
    ]


@router.post("/database/query")
def safe_query(
    body: SafeQueryRequest,
    context: Annotated[UserContext, Depends(current_user)],
    services: Annotated[Runtime, Depends(runtime)],
) -> dict[str, Any]:
    try:
        services.authorizer.authorize_tool(context, "query_safe_database")
        return services.safe_database.query(
            body.query_name, services.graph.list_files(context.workspace_id)
        )
    except (AuthorizationError, ValueError) as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
