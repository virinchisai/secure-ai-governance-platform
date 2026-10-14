from __future__ import annotations

from datetime import UTC, datetime

import pytest

from apps.api.governance.azure import azure_function_style_handler, to_logic_app_payload
from apps.api.governance.connectors import (
    ConnectorConfigurationError,
    LocalGraphSimulator,
    MicrosoftGraphProvider,
)
from apps.api.governance.demo import demo_documents
from apps.api.governance.domain import AuditEvent


def test_local_graph_lists_only_requested_workspace() -> None:
    graph = LocalGraphSimulator(demo_documents())
    documents = graph.list_files("acme-labs")
    assert documents
    assert all(document.workspace_id == "acme-labs" for document in documents)


def test_microsoft_graph_fails_closed_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConnectorConfigurationError, match="not configured"):
        MicrosoftGraphProvider()


def test_logic_app_payload_contains_decision_metadata_not_content() -> None:
    event = AuditEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        request_id="request-1",
        user_id="user-1",
        workspace_id="workspace-1",
        action="email.prepare",
        result="blocked",
        risk_score=25,
        reason="Policy block",
        event_type="dlp_violation",
    )
    payload = to_logic_app_payload(event).model_dump(mode="json")
    assert payload["severity"] == "high"
    assert "content" not in payload["data"]


def test_azure_function_style_handler_validates_and_forwards() -> None:
    forwarded: list[dict[str, object]] = []
    payload = {
        "event_type": "approval_requested",
        "severity": "informational",
        "workspace_id": "workspace-1",
        "event_id": "event-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "data": {"request_id": "request-1"},
    }
    result = azure_function_style_handler(payload, forwarded.append)
    assert result == {"status": "accepted", "event_id": "event-1"}
    assert forwarded[0]["source"] == "secure-ai-governance-platform"
