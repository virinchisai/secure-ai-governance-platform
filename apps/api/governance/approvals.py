from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any, Protocol

from .domain import ApprovalRecord, ApprovalStatus


class ApprovalError(ValueError):
    pass


class ApprovalStore(Protocol):
    def put(self, record: ApprovalRecord) -> None: ...
    def get(self, approval_id: str) -> ApprovalRecord | None: ...
    def replace(self, record: ApprovalRecord, expected: ApprovalStatus) -> bool: ...
    def list_for_workspace(self, workspace_id: str) -> list[ApprovalRecord]: ...


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

    def put(self, record: ApprovalRecord) -> None:
        with self._lock:
            self._records[record.approval_id] = record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._records.get(approval_id)

    def replace(self, record: ApprovalRecord, expected: ApprovalStatus) -> bool:
        with self._lock:
            current = self._records.get(record.approval_id)
            if current is None or current.status != expected:
                return False
            self._records[record.approval_id] = record
            return True

    def list_for_workspace(self, workspace_id: str) -> list[ApprovalRecord]:
        with self._lock:
            return [r for r in self._records.values() if r.workspace_id == workspace_id]


class ApprovalService:
    def __init__(
        self,
        signing_key: bytes,
        ttl_minutes: int = 30,
        store: ApprovalStore | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._ttl = timedelta(minutes=ttl_minutes)
        self._store = store or InMemoryApprovalStore()

    def digest(self, action: str, arguments: dict[str, Any]) -> str:
        canonical = json.dumps(
            {"action": action, "arguments": arguments}, sort_keys=True, separators=(",", ":")
        )
        return hmac.new(self._signing_key, canonical.encode(), hashlib.sha256).hexdigest()

    def request(
        self, *, workspace_id: str, requester_id: str, action: str, arguments: dict[str, Any]
    ) -> ApprovalRecord:
        record = ApprovalRecord(
            workspace_id=workspace_id,
            requester_id=requester_id,
            action=action,
            arguments_digest=self.digest(action, arguments),
            expires_at=datetime.now(UTC) + self._ttl,
        )
        self._store.put(record)
        return record

    def decide(self, approval_id: str, *, approver_id: str, approve: bool) -> ApprovalRecord:
        record = self._require(approval_id)
        if record.status != ApprovalStatus.PENDING:
            raise ApprovalError("Approval is not pending")
        if self._utc(record.expires_at) <= datetime.now(UTC):
            self._store.replace(
                record.model_copy(update={"status": ApprovalStatus.EXPIRED}),
                ApprovalStatus.PENDING,
            )
            raise ApprovalError("Approval has expired")
        updated = record.model_copy(
            update={
                "status": ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED,
                "decided_by": approver_id,
                "decided_at": datetime.now(UTC),
            }
        )
        if not self._store.replace(updated, ApprovalStatus.PENDING):
            raise ApprovalError("Approval was changed concurrently")
        return updated

    def consume(
        self, approval_id: str, *, workspace_id: str, action: str, arguments: dict[str, Any]
    ) -> ApprovalRecord:
        record = self._require(approval_id)
        if record.workspace_id != workspace_id:
            raise ApprovalError("Approval tenant does not match action tenant")
        if record.status != ApprovalStatus.APPROVED:
            raise ApprovalError("Approval is not approved or has already been used")
        if self._utc(record.expires_at) <= datetime.now(UTC):
            self._store.replace(
                record.model_copy(update={"status": ApprovalStatus.EXPIRED}),
                ApprovalStatus.APPROVED,
            )
            raise ApprovalError("Approval has expired")
        expected = self.digest(action, arguments)
        if not hmac.compare_digest(expected, record.arguments_digest):
            raise ApprovalError("Action arguments differ from approved arguments")
        consumed = record.model_copy(update={"status": ApprovalStatus.CONSUMED})
        if not self._store.replace(consumed, ApprovalStatus.APPROVED):
            raise ApprovalError("Approval was already consumed concurrently")
        return consumed

    def get(self, approval_id: str) -> ApprovalRecord:
        return self._require(approval_id)

    def list_for_workspace(self, workspace_id: str) -> list[ApprovalRecord]:
        return self._store.list_for_workspace(workspace_id)

    def _require(self, approval_id: str) -> ApprovalRecord:
        record = self._store.get(approval_id)
        if record is None:
            raise ApprovalError("Approval not found")
        return record

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
