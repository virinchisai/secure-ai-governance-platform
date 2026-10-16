from __future__ import annotations

from typing import Any

import httpx


class SIEMForwardingError(RuntimeError):
    pass


class OpenSearchForwarder:
    """Forwards normalized metadata only; audit events cannot contain document bodies."""

    def __init__(
        self,
        base_url: str,
        *,
        index: str = "governance-security-events",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.index = index
        self.transport = transport

    def __call__(self, event: dict[str, object]) -> None:
        event_id = str(event.get("event_id", ""))
        if not event_id:
            raise SIEMForwardingError("SIEM event requires event_id")
        try:
            with httpx.Client(transport=self.transport, timeout=5) as client:
                response = client.put(
                    f"{self.base_url}/{self.index}/_doc/{event_id}",
                    json=self._safe_payload(event),
                )
                response.raise_for_status()
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            raise SIEMForwardingError("OpenSearch event forwarding failed") from exc

    @staticmethod
    def _safe_payload(event: dict[str, object]) -> dict[str, Any]:
        allowed = {
            "event_id",
            "timestamp",
            "request_id",
            "user_id",
            "workspace_id",
            "action",
            "tool",
            "resource",
            "classification",
            "policy_decision",
            "policy_id",
            "approval_id",
            "result",
            "risk_score",
            "reason",
            "event_type",
        }
        return {key: value for key, value in event.items() if key in allowed}
