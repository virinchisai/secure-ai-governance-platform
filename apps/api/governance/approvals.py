from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

from .domain import ApprovalRecord, ApprovalStatus


class ApprovalError(ValueError):
    pass


class ApprovalService:
    def __init__(self, signing_key: bytes, ttl_minutes: int = 30) -> None:
        self._signing_key = signing_key
        self._ttl = timedelta(minutes=ttl_minutes)
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

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
        with self._lock:
            self._records[record.approval_id] = record
        return record

    def decide(self, approval_id: str, *, approver_id: str, approve: bool) -> ApprovalRecord:
        with self._lock:
            record = self._require(approval_id)
            if record.status != ApprovalStatus.PENDING:
                raise ApprovalError("Approval is not pending")
            if record.expires_at <= datetime.now(UTC):
                expired = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
                self._records[approval_id] = expired
                raise ApprovalError("Approval has expired")
            updated = record.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED,
                    "decided_by": approver_id,
                    "decided_at": datetime.now(UTC),
                }
            )
            self._records[approval_id] = updated
            return updated

    def consume(
        self, approval_id: str, *, workspace_id: str, action: str, arguments: dict[str, Any]
    ) -> ApprovalRecord:
        with self._lock:
            record = self._require(approval_id)
            if record.workspace_id != workspace_id:
                raise ApprovalError("Approval tenant does not match action tenant")
            if record.status != ApprovalStatus.APPROVED:
                raise ApprovalError("Approval is not approved or has already been used")
            if record.expires_at <= datetime.now(UTC):
                self._records[approval_id] = record.model_copy(
                    update={"status": ApprovalStatus.EXPIRED}
                )
                raise ApprovalError("Approval has expired")
            expected = self.digest(action, arguments)
            if not hmac.compare_digest(expected, record.arguments_digest):
                raise ApprovalError("Action arguments differ from approved arguments")
            consumed = record.model_copy(update={"status": ApprovalStatus.CONSUMED})
            self._records[approval_id] = consumed
            return consumed

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._lock:
            return self._require(approval_id)

    def list_for_workspace(self, workspace_id: str) -> list[ApprovalRecord]:
        with self._lock:
            return [
                record for record in self._records.values() if record.workspace_id == workspace_id
            ]

    def _require(self, approval_id: str) -> ApprovalRecord:
        try:
            return self._records[approval_id]
        except KeyError as exc:
            raise ApprovalError("Approval not found") from exc
