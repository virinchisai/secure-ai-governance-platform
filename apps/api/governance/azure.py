from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from .domain import AuditEvent


class LogicAppEnvelope(BaseModel):
    schema_version: str = "1.0"
    source: str = "secure-ai-governance-platform"
    event_type: str
    severity: str
    workspace_id: str
    event_id: str
    timestamp: str
    data: dict[str, Any] = Field(default_factory=dict)


def to_logic_app_payload(event: AuditEvent) -> LogicAppEnvelope:
    """Azure Logic Apps-style payload builder; it does not deploy or call Azure."""
    severity = "high" if event.result in {"blocked", "denied"} else "informational"
    return LogicAppEnvelope(
        event_type=event.event_type,
        severity=severity,
        workspace_id=event.workspace_id,
        event_id=event.event_id,
        timestamp=event.timestamp.isoformat(),
        data={
            "request_id": event.request_id,
            "action": event.action,
            "policy_id": event.policy_id,
            "policy_decision": event.policy_decision,
            "risk_score": event.risk_score,
            "result": event.result,
        },
    )


def azure_function_style_handler(
    payload: dict[str, Any], forward: Callable[[dict[str, Any]], None]
) -> dict[str, str]:
    """Framework-neutral handler shaped for an Azure Function HTTP trigger."""
    envelope = LogicAppEnvelope.model_validate(payload)
    forward(envelope.model_dump(mode="json"))
    return {"status": "accepted", "event_id": envelope.event_id}
