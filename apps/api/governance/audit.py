from __future__ import annotations

import json
from collections.abc import Callable
from threading import Lock

import structlog

from .domain import AuditEvent

logger = structlog.get_logger("security.audit")


class AuditSink:
    def emit(self, event: AuditEvent) -> None:
        raise NotImplementedError

    def list_events(self, workspace_id: str) -> list[AuditEvent]:
        raise NotImplementedError


class InMemoryAuditSink(AuditSink):
    def __init__(self, forwarder: Callable[[dict[str, object]], None] | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()
        self._forwarder = forwarder

    def emit(self, event: AuditEvent) -> None:
        payload = json.loads(event.model_dump_json())
        with self._lock:
            self._events.append(event)
        logger.info("security_event", **payload)
        if self._forwarder:
            self._forwarder(payload)

    def list_events(self, workspace_id: str) -> list[AuditEvent]:
        with self._lock:
            return [event for event in self._events if event.workspace_id == workspace_id]


class JsonLinesAuditSink(InMemoryAuditSink):
    """Writes normalized SIEM-ready JSON lines. Raw sensitive content is never accepted."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path

    def emit(self, event: AuditEvent) -> None:
        super().emit(event)
        with open(self.path, "a", encoding="utf-8") as handle:  # noqa: PTH123
            handle.write(event.model_dump_json() + "\n")
