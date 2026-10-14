from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    USER = "user"
    ANALYST = "analyst"
    SECURITY_ADMIN = "security_admin"
    COMPLIANCE_ADMIN = "compliance_admin"


class ClassificationLevel(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_CONFIDENTIAL = "HIGHLY_CONFIDENTIAL"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class UserContext(BaseModel):
    user_id: str
    workspace_id: str
    roles: frozenset[Role]


class UserRecord(BaseModel):
    user_id: str
    username: str
    workspace_id: str
    roles: frozenset[Role]
    password_hash: str
    active: bool = True


class DetectedEntity(BaseModel):
    entity_type: str
    start: int
    end: int
    masked_value: str
    confidence: float = Field(ge=0, le=1)


class ClassificationResult(BaseModel):
    classification: ClassificationLevel
    sensitivity_label: str
    entities: list[DetectedEntity]
    confidence: float = Field(ge=0, le=1)
    reasons: list[str]
    applicable_policies: list[str]


class DLPDecision(BaseModel):
    decision: PolicyDecision
    policy_id: str
    rule_matched: str
    reason: str
    affected_data: list[str]
    redacted_content: str | None = None


class Document(BaseModel):
    document_id: str
    workspace_id: str
    name: str
    content: str
    owner_id: str


class ActionRequest(BaseModel):
    action: str
    arguments: dict[str, Any]


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    workspace_id: str
    requester_id: str
    action: str
    arguments_digest: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_id: str
    user_id: str
    workspace_id: str
    action: str
    tool: str | None = None
    resource: str | None = None
    classification: ClassificationLevel | None = None
    policy_decision: PolicyDecision | None = None
    policy_id: str | None = None
    approval_id: str | None = None
    result: str
    risk_score: int = Field(ge=0, le=100)
    reason: str
    event_type: str


class RiskSignal(BaseModel):
    signal_id: str
    name: str
    score: int
    reason: str


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    signals: list[RiskSignal]


class ToolTrace(BaseModel):
    tool: str
    status: str
    detail: str


class AgentResponse(BaseModel):
    request_id: str
    status: str
    summary: str | None = None
    sources: list[str]
    classifications: list[ClassificationResult]
    policy_decision: DLPDecision
    approval_id: str | None = None
    tool_trace: list[ToolTrace]
