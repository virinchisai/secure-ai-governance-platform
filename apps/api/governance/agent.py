from __future__ import annotations

import re
from uuid import uuid4

from .ai import AIProvider
from .approvals import ApprovalService
from .audit import AuditSink
from .cache import SemanticCache
from .classification import DataClassifier
from .connectors import GraphProvider
from .dlp import DLPEngine
from .domain import (
    AgentResponse,
    AuditEvent,
    ClassificationLevel,
    ClassificationResult,
    DLPDecision,
    PolicyDecision,
    ToolTrace,
    UserContext,
)
from .injection import PromptInjectionDetector
from .rbac import AuthorizationError, RBACAuthorizer
from .risk import InsiderRiskEngine

EMAIL_PATTERN = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.I)


class AgentSecurityError(ValueError):
    pass


class SecureAgent:
    """Bounded workflow. It never executes model-selected tools."""

    def __init__(
        self,
        *,
        graph: GraphProvider,
        ai: AIProvider,
        classifier: DataClassifier,
        dlp: DLPEngine,
        injection: PromptInjectionDetector,
        authorizer: RBACAuthorizer,
        approvals: ApprovalService,
        audit: AuditSink,
        risk: InsiderRiskEngine,
        cache: SemanticCache,
        internal_domains: frozenset[str] = frozenset({"example.corp"}),
    ) -> None:
        self.graph = graph
        self.ai = ai
        self.classifier = classifier
        self.dlp = dlp
        self.injection = injection
        self.authorizer = authorizer
        self.approvals = approvals
        self.audit = audit
        self.risk = risk
        self.cache = cache
        self.internal_domains = internal_domains

    def summarize_and_email(
        self,
        *,
        context: UserContext,
        document_ids: list[str],
        recipient: str,
        request_id: str | None = None,
    ) -> AgentResponse:
        request_id = request_id or str(uuid4())
        trace: list[ToolTrace] = []
        self._validate_recipient(recipient)
        external = recipient.rsplit("@", 1)[1].lower() not in self.internal_domains
        documents = []
        for document_id in document_ids:
            try:
                self.authorizer.authorize_tool(context, "get_document")
                document = self.graph.read_file(context.workspace_id, document_id)
                self.authorizer.authorize_workspace(context, document.workspace_id)
            except (AuthorizationError, LookupError) as exc:
                risk = self.risk.record(context.user_id, "failed_authorization")
                self._audit(
                    request_id,
                    context,
                    "document.read",
                    "get_document",
                    document_id,
                    "denied",
                    risk.score,
                    str(exc),
                    "unauthorized_tool_call",
                )
                raise AgentSecurityError("Document access denied") from exc
            documents.append(document)
            access_risk = self.risk.record(context.user_id, "document_access")
            if self.risk.counters(context.user_id).get("document_access") == 15:
                self._audit(
                    request_id,
                    context,
                    "document.bulk_access",
                    "get_document",
                    "workspace_documents",
                    "signaled",
                    access_risk.score,
                    "Document access threshold reached",
                    "suspicious_bulk_access",
                )
            trace.append(ToolTrace(tool="get_document", status="allowed", detail=document.name))

        if not documents:
            raise AgentSecurityError("At least one document is required")

        sanitized: list[str] = []
        for document in documents:
            finding = self.injection.inspect(document.content)
            if finding.detected:
                risk = self.risk.record(context.user_id, "sensitive_enumeration")
                self._audit(
                    request_id,
                    context,
                    "content.inspect",
                    "prompt_injection_detector",
                    document.document_id,
                    "detected",
                    risk.score,
                    finding.reason,
                    "prompt_injection_detected",
                )
                trace.append(
                    ToolTrace(
                        tool="prompt_injection_detector",
                        status="contained",
                        detail=", ".join(finding.patterns),
                    )
                )
            sanitized.append(self.injection.isolate_untrusted_content(document.content))

        source_text = "\n".join(document.content for document in documents)
        source_classification = self.classifier.classify(source_text)
        trace.append(
            ToolTrace(
                tool="classify_document",
                status="complete",
                detail=source_classification.sensitivity_label,
            )
        )
        cache_context = {
            "workspace_id": context.workspace_id,
            "user_id": context.user_id,
            "authorization_context": {role.value for role in context.roles},
            "prompt": "summarize:" + "\n".join(sanitized),
        }
        source_is_sensitive = source_classification.classification in {
            ClassificationLevel.CONFIDENTIAL,
            ClassificationLevel.HIGHLY_CONFIDENTIAL,
        }
        summary = None if source_is_sensitive else self.cache.get(**cache_context)
        if summary is None:
            summary = self.ai.summarize(sanitized)
            self.cache.put(value=summary, sensitive=source_is_sensitive, **cache_context)
            trace.append(ToolTrace(tool="semantic_cache", status="miss", detail="Provider invoked"))
        else:
            trace.append(
                ToolTrace(tool="semantic_cache", status="hit", detail="Authorization-scoped")
            )
        output_classification = self.classifier.classify(summary)
        classification = self._max_classification(source_classification, output_classification)
        decision = self.dlp.evaluate(
            content=summary, classification=classification, external=external, roles=context.roles
        )
        trace.append(
            ToolTrace(
                tool="check_dlp_policy",
                status=decision.decision.value.lower(),
                detail=f"{decision.policy_id}: {decision.rule_matched}",
            )
        )

        if external:
            self.risk.record(context.user_id, "external_share_attempt")
        if decision.decision == PolicyDecision.BLOCK:
            risk = self.risk.record(context.user_id, "blocked_export")
            event_type = (
                "secret_detected"
                if decision.policy_id == "DLP-SECRET-001"
                else "sensitive_data_external_share_attempt"
            )
            self._audit(
                request_id,
                context,
                "email.prepare",
                "send_email",
                recipient,
                "blocked",
                risk.score,
                decision.reason,
                event_type,
                classification,
                decision,
            )
            return AgentResponse(
                request_id=request_id,
                status="blocked",
                summary=None,
                sources=document_ids,
                classifications=[source_classification, output_classification],
                policy_decision=decision,
                tool_trace=trace,
            )

        if decision.decision == PolicyDecision.REDACT:
            summary = decision.redacted_content or summary
            output_classification = self.classifier.classify(summary)
            decision = self.dlp.evaluate(
                content=summary,
                classification=output_classification,
                external=external,
                roles=context.roles,
            )

        arguments: dict[str, object] = {
            "recipient": recipient.lower(),
            "subject": "Document summary",
            "body": summary,
            "document_ids": sorted(document_ids),
        }
        if decision.decision == PolicyDecision.REQUIRE_APPROVAL:
            self.authorizer.authorize_tool(context, "draft_email")
            approval = self.approvals.request(
                workspace_id=context.workspace_id,
                requester_id=context.user_id,
                action="send_email",
                arguments=arguments,
            )
            risk = self.risk.assess(context.user_id)
            self._audit(
                request_id,
                context,
                "email.approval.request",
                "send_email",
                recipient,
                "pending",
                risk.score,
                decision.reason,
                "approval_requested",
                classification,
                decision,
                approval.approval_id,
            )
            trace.append(
                ToolTrace(tool="send_email", status="pending_approval", detail=approval.approval_id)
            )
            return AgentResponse(
                request_id=request_id,
                status="pending_approval",
                summary=summary,
                sources=document_ids,
                classifications=[source_classification, output_classification],
                policy_decision=decision,
                approval_id=approval.approval_id,
                tool_trace=trace,
            )

        return self._send(
            context=context,
            arguments=arguments,
            request_id=request_id,
            decision=decision,
            trace=trace,
        )

    def execute_approved_email(
        self,
        *,
        context: UserContext,
        approval_id: str,
        arguments: dict[str, object],
        request_id: str | None = None,
    ) -> AgentResponse:
        request_id = request_id or str(uuid4())
        self.authorizer.authorize_tool(context, "send_email")
        self.approvals.consume(
            approval_id, workspace_id=context.workspace_id, action="send_email", arguments=arguments
        )
        classification = self.classifier.classify(str(arguments.get("body", "")))
        decision = self.dlp.evaluate(
            content=str(arguments.get("body", "")),
            classification=classification,
            external=True,
            roles=context.roles,
        )
        if decision.decision == PolicyDecision.BLOCK:
            raise AgentSecurityError("Approved action failed output inspection")
        trace = [ToolTrace(tool="approval", status="consumed", detail=approval_id)]
        return self._send(
            context=context,
            arguments=arguments,
            request_id=request_id,
            decision=decision,
            trace=trace,
            approval_id=approval_id,
        )

    def _send(
        self,
        *,
        context: UserContext,
        arguments: dict[str, object],
        request_id: str,
        decision: DLPDecision,
        trace: list[ToolTrace],
        approval_id: str | None = None,
    ) -> AgentResponse:
        self.authorizer.authorize_tool(context, "send_email")
        recipient = str(arguments["recipient"])
        self._validate_recipient(recipient)
        body = str(arguments["body"])
        final_classification = self.classifier.classify(body)
        final_decision = self.dlp.evaluate(
            content=body,
            classification=final_classification,
            external=recipient.rsplit("@", 1)[1].lower() not in self.internal_domains,
            roles=context.roles,
        )
        if (
            final_decision.decision in {PolicyDecision.BLOCK, PolicyDecision.REQUIRE_APPROVAL}
            and approval_id is None
        ):
            raise AgentSecurityError("Write action did not pass final policy enforcement")
        draft_id = self.graph.create_draft(
            context.workspace_id, recipient, str(arguments["subject"]), body
        )
        message_id = self.graph.send_message(context.workspace_id, draft_id)
        risk = self.risk.assess(context.user_id)
        self._audit(
            request_id,
            context,
            "email.send",
            "send_email",
            recipient,
            "sent",
            risk.score,
            "Validated connector action completed",
            "external_message_sent",
            final_classification.classification,
            final_decision,
            approval_id,
        )
        trace.extend(
            [
                ToolTrace(tool="draft_email", status="complete", detail=draft_id),
                ToolTrace(tool="send_email", status="complete", detail=message_id),
            ]
        )
        source_ids = arguments.get("document_ids", [])
        if not isinstance(source_ids, list):
            raise AgentSecurityError("Document IDs must be a list")
        return AgentResponse(
            request_id=request_id,
            status="sent",
            summary=body,
            sources=[str(item) for item in source_ids],
            classifications=[final_classification],
            policy_decision=final_decision,
            approval_id=approval_id,
            tool_trace=trace,
        )

    @staticmethod
    def _validate_recipient(recipient: str) -> None:
        if len(recipient) > 254 or not EMAIL_PATTERN.fullmatch(recipient):
            raise AgentSecurityError("Invalid recipient address")

    @staticmethod
    def _max_classification(
        first: ClassificationResult, second: ClassificationResult
    ) -> ClassificationResult:
        from .classification import LEVEL_RANK

        return (
            first
            if LEVEL_RANK[first.classification] >= LEVEL_RANK[second.classification]
            else second
        )

    def _audit(
        self,
        request_id: str,
        context: UserContext,
        action: str,
        tool: str,
        resource: str,
        result: str,
        risk_score: int,
        reason: str,
        event_type: str,
        classification: ClassificationLevel | ClassificationResult | None = None,
        decision: DLPDecision | None = None,
        approval_id: str | None = None,
    ) -> None:
        level = (
            classification.classification
            if isinstance(classification, ClassificationResult)
            else classification
        )
        self.audit.emit(
            AuditEvent(
                request_id=request_id,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                action=action,
                tool=tool,
                resource=resource,
                classification=level,
                policy_decision=decision.decision if decision else None,
                policy_id=decision.policy_id if decision else None,
                approval_id=approval_id,
                result=result,
                risk_score=risk_score,
                reason=reason,
                event_type=event_type,
            )
        )
