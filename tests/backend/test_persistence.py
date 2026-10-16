from pathlib import Path

from apps.api.governance.approvals import ApprovalError, ApprovalService
from apps.api.governance.domain import AuditEvent
from apps.api.governance.persistence import DatabaseApprovalStore, DatabaseAuditSink


def test_database_approval_survives_service_recreation(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'state.db'}"
    arguments = {"recipient": "outside@example.test", "body": "approved"}
    first = ApprovalService(b"key", store=DatabaseApprovalStore(url))
    record = first.request(
        workspace_id="workspace-a", requester_id="user-a", action="send", arguments=arguments
    )
    first.decide(record.approval_id, approver_id="admin", approve=True)
    second = ApprovalService(b"key", store=DatabaseApprovalStore(url))
    consumed = second.consume(
        record.approval_id,
        workspace_id="workspace-a",
        action="send",
        arguments=arguments,
    )
    assert consumed.status.value == "CONSUMED"


def test_database_approval_remains_single_use(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'state.db'}"
    service = ApprovalService(b"key", store=DatabaseApprovalStore(url))
    record = service.request(workspace_id="w", requester_id="u", action="send", arguments={})
    service.decide(record.approval_id, approver_id="admin", approve=True)
    service.consume(record.approval_id, workspace_id="w", action="send", arguments={})
    try:
        service.consume(record.approval_id, workspace_id="w", action="send", arguments={})
    except ApprovalError:
        pass
    else:
        raise AssertionError("durable approval was reused")


def test_database_audit_is_tenant_scoped_and_durable(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'audit.db'}"
    sink = DatabaseAuditSink(url)
    for workspace in ("workspace-a", "workspace-b"):
        sink.emit(
            AuditEvent(
                request_id=f"request-{workspace}",
                user_id="user",
                workspace_id=workspace,
                action="test",
                result="allowed",
                risk_score=0,
                reason="test",
                event_type="test_event",
            )
        )
    recreated = DatabaseAuditSink(url)
    events = recreated.list_events("workspace-a")
    assert len(events) == 1
    assert events[0].workspace_id == "workspace-a"
