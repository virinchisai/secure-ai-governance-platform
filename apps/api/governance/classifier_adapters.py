from __future__ import annotations

import httpx

from .classification import LEVEL_RANK, DataClassifier
from .domain import ClassificationLevel, ClassificationResult, DetectedEntity


class ClassifierProviderError(RuntimeError):
    pass


PRESIDIO_LEVELS = {
    "US_SSN": ClassificationLevel.HIGHLY_CONFIDENTIAL,
    "CREDIT_CARD": ClassificationLevel.HIGHLY_CONFIDENTIAL,
    "EMAIL_ADDRESS": ClassificationLevel.CONFIDENTIAL,
    "PHONE_NUMBER": ClassificationLevel.CONFIDENTIAL,
    "PERSON": ClassificationLevel.CONFIDENTIAL,
    "IBAN_CODE": ClassificationLevel.HIGHLY_CONFIDENTIAL,
}


class PresidioClassifier(DataClassifier):
    """Combines local secret rules with a self-hosted Presidio analyzer."""

    def __init__(self, base_url: str, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=10)

    def classify(self, content: str) -> ClassificationResult:
        local = super().classify(content)
        try:
            response = self.client.post(
                f"{self.base_url}/analyze", json={"text": content, "language": "en"}
            )
            response.raise_for_status()
            findings = response.json()
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            raise ClassifierProviderError("Presidio classification unavailable") from exc

        entities = list(local.entities)
        level = local.classification
        reasons = list(local.reasons)
        confidence = local.confidence
        for finding in findings:
            entity_type = str(finding["entity_type"])
            entity_level = PRESIDIO_LEVELS.get(entity_type, ClassificationLevel.INTERNAL)
            start, end = int(finding["start"]), int(finding["end"])
            score = float(finding["score"])
            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    masked_value=self._mask(content[start:end]),
                    confidence=score,
                )
            )
            if LEVEL_RANK[entity_level] > LEVEL_RANK[level]:
                level = entity_level
            confidence = max(confidence, score)
            if entity_type not in reasons:
                reasons.append(entity_type)
        label = (
            "Restricted External Sharing"
            if level == ClassificationLevel.HIGHLY_CONFIDENTIAL
            else level.value.replace("_", " ").title()
        )
        return local.model_copy(
            update={
                "classification": level,
                "sensitivity_label": label,
                "entities": entities,
                "confidence": confidence,
                "reasons": reasons,
            }
        )
