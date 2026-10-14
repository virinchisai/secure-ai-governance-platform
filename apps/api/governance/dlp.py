from __future__ import annotations

from .classification import DataClassifier
from .domain import ClassificationLevel, ClassificationResult, DLPDecision, PolicyDecision, Role


class DLPEngine:
    """Ordered deterministic policies. First matching rule wins."""

    def evaluate(
        self,
        *,
        content: str,
        classification: ClassificationResult,
        external: bool,
        roles: frozenset[Role],
    ) -> DLPDecision:
        entity_types = sorted({entity.entity_type for entity in classification.entities})
        if "API_KEY" in entity_types or "SECRET" in entity_types:
            return DLPDecision(
                decision=PolicyDecision.BLOCK,
                policy_id="DLP-SECRET-001",
                rule_matched="block_secrets_in_output",
                reason="Secrets may not be included in model or connector output.",
                affected_data=[kind for kind in entity_types if kind in {"API_KEY", "SECRET"}],
            )
        if external and classification.classification == ClassificationLevel.HIGHLY_CONFIDENTIAL:
            return DLPDecision(
                decision=PolicyDecision.BLOCK,
                policy_id="DLP-EXT-001",
                rule_matched="block_highly_confidential_external_share",
                reason="Highly confidential data cannot be shared externally.",
                affected_data=entity_types,
            )
        high_risk_pii = {"SSN", "PAYMENT_CARD"}.intersection(entity_types)
        if high_risk_pii:
            return DLPDecision(
                decision=PolicyDecision.REDACT,
                policy_id="DLP-PII-001",
                rule_matched="redact_high_risk_pii",
                reason="High-risk PII must be redacted before use.",
                affected_data=sorted(high_risk_pii),
                redacted_content=DataClassifier.redact(content, classification, high_risk_pii),
            )
        if external and classification.classification == ClassificationLevel.CONFIDENTIAL:
            return DLPDecision(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                policy_id="DLP-EXT-002",
                rule_matched="approval_for_confidential_external_share",
                reason="Confidential external sharing requires compliance approval.",
                affected_data=entity_types,
            )
        if not external and roles.intersection(
            {Role.USER, Role.ANALYST, Role.SECURITY_ADMIN, Role.COMPLIANCE_ADMIN}
        ):
            return DLPDecision(
                decision=PolicyDecision.ALLOW,
                policy_id="DLP-INTERNAL-001",
                rule_matched="allow_authorized_internal_share",
                reason="The authenticated role may use this classification internally.",
                affected_data=entity_types,
            )
        if external and classification.classification in {
            ClassificationLevel.PUBLIC,
            ClassificationLevel.INTERNAL,
        }:
            return DLPDecision(
                decision=PolicyDecision.ALLOW,
                policy_id="DLP-EXT-003",
                rule_matched="allow_low_sensitivity_external_share",
                reason="No restricted data was detected.",
                affected_data=entity_types,
            )
        return DLPDecision(
            decision=PolicyDecision.BLOCK,
            policy_id="DLP-DEFAULT-000",
            rule_matched="default_deny",
            reason="No allow policy matched.",
            affected_data=entity_types,
        )
