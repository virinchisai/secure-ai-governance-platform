from fastapi.testclient import TestClient

from apps.api.governance.domain import PolicyDecision, Role, UserContext
from tests.backend.conftest import login


def test_normal_internal_retrieval_and_send_succeeds(runtime, analyst: UserContext) -> None:
    response = runtime.agent.summarize_and_email(
        context=analyst, document_ids=["public-product-brief"], recipient="team@example.corp"
    )
    assert response.status == "sent"
    assert response.policy_decision.decision == PolicyDecision.ALLOW


def test_sensitive_external_share_is_blocked(runtime, analyst: UserContext) -> None:
    response = runtime.agent.summarize_and_email(
        context=analyst, document_ids=["employee-record"], recipient="outside@example.net"
    )
    assert response.status == "blocked"
    assert response.summary is None
    assert response.policy_decision.policy_id == "DLP-EXT-001"


def test_confidential_external_share_requests_approval(runtime, analyst: UserContext) -> None:
    response = runtime.agent.summarize_and_email(
        context=analyst, document_ids=["customer-contract"], recipient="outside@example.net"
    )
    assert response.status == "pending_approval"
    assert response.approval_id


def test_prompt_injection_is_contained_and_audited(runtime, analyst: UserContext) -> None:
    response = runtime.agent.summarize_and_email(
        context=analyst, document_ids=["injection-sample"], recipient="team@example.corp"
    )
    assert response.status == "sent"
    assert "Ignore previous instructions" not in (response.summary or "")
    assert analyst.roles == frozenset({Role.ANALYST})
    events = runtime.audit.list_events("acme-labs")
    assert any(event.event_type == "prompt_injection_detected" for event in events)


def test_blocked_action_generates_policy_audit_event(runtime, analyst: UserContext) -> None:
    runtime.agent.summarize_and_email(
        context=analyst, document_ids=["employee-record"], recipient="outside@example.net"
    )
    events = runtime.audit.list_events("acme-labs")
    event = next(
        item for item in events if item.event_type == "sensitive_data_external_share_attempt"
    )
    assert event.policy_id == "DLP-EXT-001"
    assert event.policy_decision == PolicyDecision.BLOCK


def test_cross_tenant_document_is_not_retrievable(runtime, analyst: UserContext) -> None:
    try:
        runtime.agent.summarize_and_email(
            context=analyst, document_ids=["other-tenant-document"], recipient="team@example.corp"
        )
    except ValueError as exc:
        assert "denied" in str(exc)
    else:
        raise AssertionError("cross-tenant retrieval was not blocked")


def test_login_and_document_api_are_authenticated(client: TestClient) -> None:
    assert client.get("/api/documents").status_code == 401
    headers = login(client)
    response = client.get("/api/documents", headers=headers)
    assert response.status_code == 200
    assert all(document["workspace_id"] == "acme-labs" for document in response.json())


def test_invalid_login_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "analyst@acme.test", "password": "wrong"}
    )
    assert response.status_code == 401


def test_api_sensitive_external_share_blocked(client: TestClient) -> None:
    response = client.post(
        "/api/agent/summarize-email",
        headers=login(client),
        json={"document_ids": ["employee-record"], "recipient": "outside@example.net"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "blocked"


def test_basic_user_cannot_execute_send(client: TestClient) -> None:
    headers = login(client, "user@acme.test", "Demo-User-2026!")
    response = client.post(
        "/api/agent/summarize-email",
        headers=headers,
        json={"document_ids": ["public-product-brief"], "recipient": "team@example.corp"},
    )
    assert response.status_code == 403


def test_safe_database_rejects_arbitrary_query(client: TestClient) -> None:
    response = client.post(
        "/api/database/query", headers=login(client), json={"query_name": "DROP TABLE users"}
    )
    assert response.status_code == 403


def test_approval_decision_is_audited(client: TestClient) -> None:
    analyst_headers = login(client)
    pending = client.post(
        "/api/agent/summarize-email",
        headers=analyst_headers,
        json={"document_ids": ["customer-contract"], "recipient": "outside@example.net"},
    ).json()
    compliance_headers = login(client, "compliance@acme.test", "Demo-Compliance-2026!")
    decision = client.post(
        f"/api/approvals/{pending['approval_id']}/decision",
        headers=compliance_headers,
        json={"approve": True},
    )
    assert decision.status_code == 200
    events = client.get("/api/audit", headers=compliance_headers).json()
    assert any(event["event_type"] == "approval_granted" for event in events)
