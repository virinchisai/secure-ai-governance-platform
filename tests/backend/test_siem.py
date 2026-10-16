import json

import httpx

from apps.api.governance.audit import ForwardingAuditSink, InMemoryAuditSink
from apps.api.governance.domain import AuditEvent
from apps.api.governance.siem import OpenSearchForwarder, SIEMForwardingError


def test_opensearch_forwarder_sends_allowlisted_metadata_only() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        assert request.url.path == "/governance-security-events/_doc/event-1"
        return httpx.Response(201)

    forwarder = OpenSearchForwarder("http://search.test", transport=httpx.MockTransport(handler))
    forwarder(
        {
            "event_id": "event-1",
            "workspace_id": "tenant-a",
            "event_type": "dlp_violation",
            "raw_document": "must not leave the service",
        }
    )

    assert captured["workspace_id"] == "tenant-a"
    assert "raw_document" not in captured


def test_opensearch_forwarder_rejects_missing_event_id() -> None:
    forwarder = OpenSearchForwarder("http://search.test")

    try:
        forwarder({"event_type": "dlp_violation"})
    except SIEMForwardingError as exc:
        assert "event_id" in str(exc)
    else:
        raise AssertionError("missing event_id should fail")


def test_forwarding_outage_does_not_discard_local_audit_event() -> None:
    primary = InMemoryAuditSink()

    def unavailable(_event: dict[str, object]) -> None:
        raise SIEMForwardingError("unavailable")

    sink = ForwardingAuditSink(primary, unavailable)
    event = AuditEvent(
        request_id="request-1",
        user_id="user-1",
        workspace_id="tenant-a",
        action="policy.evaluate",
        result="blocked",
        risk_score=0,
        reason="test event",
        event_type="dlp_violation",
    )

    sink.emit(event)

    assert primary.list_events("tenant-a") == [event]
