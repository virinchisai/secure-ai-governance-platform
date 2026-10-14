from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime

from .domain import RiskAssessment, RiskSignal


class InsiderRiskEngine:
    """Explainable local rules; not Microsoft Insider Risk Management."""

    def __init__(self) -> None:
        self._counts: dict[str, Counter[str]] = defaultdict(Counter)

    def record(
        self, user_id: str, event_name: str, *, occurred_at: datetime | None = None
    ) -> RiskAssessment:
        self._counts[user_id][event_name] += 1
        return self.assess(user_id, occurred_at=occurred_at)

    def assess(self, user_id: str, *, occurred_at: datetime | None = None) -> RiskAssessment:
        counts = self._counts[user_id]
        signals: list[RiskSignal] = []
        now = occurred_at or datetime.now(UTC)
        rules = (
            ("document_access", 15, 20, "abnormal_bulk_access", "15 or more document accesses"),
            ("blocked_export", 3, 25, "repeated_blocked_export", "3 or more blocked exports"),
            (
                "external_share_attempt",
                4,
                20,
                "repeated_external_share",
                "4 or more external share attempts",
            ),
            (
                "failed_authorization",
                5,
                25,
                "excessive_failed_authorization",
                "5 or more failed authorization checks",
            ),
            (
                "sensitive_enumeration",
                2,
                20,
                "sensitive_file_enumeration",
                "repeated sensitive-file enumeration",
            ),
            (
                "privilege_sensitive_action",
                2,
                15,
                "privilege_sensitive_actions",
                "repeated privilege-sensitive actions",
            ),
        )
        for event, threshold, score, signal_id, reason in rules:
            if counts[event] >= threshold:
                signals.append(
                    RiskSignal(signal_id=signal_id, name=signal_id, score=score, reason=reason)
                )
        if now.hour < 6 or now.hour >= 22:
            signals.append(
                RiskSignal(
                    signal_id="unusual_access_time",
                    name="unusual_access_time",
                    score=10,
                    reason="Access occurred outside 06:00-22:00 UTC",
                )
            )
        return RiskAssessment(
            score=min(100, sum(signal.score for signal in signals)), signals=signals
        )

    def counters(self, user_id: str) -> dict[str, int]:
        return dict(self._counts[user_id])
