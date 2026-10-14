from __future__ import annotations

import re
from dataclasses import dataclass

from .domain import ClassificationLevel, ClassificationResult, DetectedEntity


@dataclass(frozen=True)
class PatternRule:
    entity_type: str
    pattern: re.Pattern[str]
    level: ClassificationLevel
    confidence: float


RULES = (
    PatternRule(
        "SSN",
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        ClassificationLevel.HIGHLY_CONFIDENTIAL,
        0.99,
    ),
    PatternRule(
        "PAYMENT_CARD",
        re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        ClassificationLevel.HIGHLY_CONFIDENTIAL,
        0.9,
    ),
    PatternRule(
        "API_KEY",
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|DEMO_API_KEY_[A-Z0-9]{12,})\b"),
        ClassificationLevel.HIGHLY_CONFIDENTIAL,
        0.99,
    ),
    PatternRule(
        "SECRET",
        re.compile(r"(?i)\b(?:password|client_secret|secret)\s*[:=]\s*[^\s,;]{6,}"),
        ClassificationLevel.HIGHLY_CONFIDENTIAL,
        0.95,
    ),
    PatternRule(
        "EMAIL",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        ClassificationLevel.CONFIDENTIAL,
        0.95,
    ),
    PatternRule(
        "PHONE",
        re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"),
        ClassificationLevel.CONFIDENTIAL,
        0.85,
    ),
    PatternRule(
        "CUSTOMER_ID",
        re.compile(r"\bCUST-[A-Z0-9]{6,12}\b"),
        ClassificationLevel.CONFIDENTIAL,
        0.95,
    ),
    PatternRule(
        "FINANCIAL",
        re.compile(
            r"(?i)\b(?:revenue|forecast|margin|bank account|routing number|quarterly results)\b"
        ),
        ClassificationLevel.CONFIDENTIAL,
        0.8,
    ),
)

LEVEL_RANK = {
    ClassificationLevel.PUBLIC: 0,
    ClassificationLevel.INTERNAL: 1,
    ClassificationLevel.CONFIDENTIAL: 2,
    ClassificationLevel.HIGHLY_CONFIDENTIAL: 3,
}

LABELS = {
    ClassificationLevel.PUBLIC: "Public",
    ClassificationLevel.INTERNAL: "Internal",
    ClassificationLevel.CONFIDENTIAL: "Confidential",
    ClassificationLevel.HIGHLY_CONFIDENTIAL: "Highly Confidential",
}


class DataClassifier:
    """Deterministic Purview-style local classification; no Microsoft service is called."""

    def classify(self, content: str) -> ClassificationResult:
        entities: list[DetectedEntity] = []
        level = (
            ClassificationLevel.PUBLIC
            if "public" in content.lower()
            else ClassificationLevel.INTERNAL
        )
        confidence = 0.7
        reasons: list[str] = [
            "baseline_public_marker" if level == ClassificationLevel.PUBLIC else "baseline_internal"
        ]
        for rule in RULES:
            for match in rule.pattern.finditer(content):
                entities.append(
                    DetectedEntity(
                        entity_type=rule.entity_type,
                        start=match.start(),
                        end=match.end(),
                        masked_value=self._mask(match.group()),
                        confidence=rule.confidence,
                    )
                )
                if LEVEL_RANK[rule.level] > LEVEL_RANK[level]:
                    level = rule.level
                confidence = max(confidence, rule.confidence)
                if rule.entity_type not in reasons:
                    reasons.append(rule.entity_type)
        label = (
            "Restricted External Sharing"
            if level == ClassificationLevel.HIGHLY_CONFIDENTIAL
            else LABELS[level]
        )
        policies = ["DLP-EXT-001", "DLP-SECRET-001"] if entities else ["DLP-INTERNAL-001"]
        return ClassificationResult(
            classification=level,
            sensitivity_label=label,
            entities=entities,
            confidence=confidence,
            reasons=reasons,
            applicable_policies=policies,
        )

    @staticmethod
    def redact(
        content: str, result: ClassificationResult, entity_types: set[str] | None = None
    ) -> str:
        selected = [
            e for e in result.entities if entity_types is None or e.entity_type in entity_types
        ]
        redacted = content
        for entity in sorted(selected, key=lambda item: item.start, reverse=True):
            redacted = (
                redacted[: entity.start]
                + f"[{entity.entity_type}_REDACTED]"
                + redacted[entity.end :]
            )
        return redacted

    @staticmethod
    def _mask(value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * min(8, len(value) - 4)}{value[-2:]}"
