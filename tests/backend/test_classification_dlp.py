from apps.api.governance.classification import DataClassifier
from apps.api.governance.dlp import DLPEngine
from apps.api.governance.domain import ClassificationLevel, PolicyDecision, Role


def test_public_marker_classifies_public() -> None:
    result = DataClassifier().classify("PUBLIC: approved brochure")
    assert result.classification == ClassificationLevel.PUBLIC
    assert result.sensitivity_label == "Public"


def test_default_classifies_internal() -> None:
    result = DataClassifier().classify("routine team notes")
    assert result.classification == ClassificationLevel.INTERNAL


def test_email_and_customer_id_are_confidential_and_masked() -> None:
    result = DataClassifier().classify("Email demo@example.test about CUST-ABC123")
    assert result.classification == ClassificationLevel.CONFIDENTIAL
    assert {item.entity_type for item in result.entities} == {"EMAIL", "CUSTOMER_ID"}
    assert all("example.test" not in item.masked_value for item in result.entities)


def test_ssn_is_highly_confidential() -> None:
    result = DataClassifier().classify("Synthetic SSN 000-12-3456")
    assert result.classification == ClassificationLevel.HIGHLY_CONFIDENTIAL
    assert result.sensitivity_label == "Restricted External Sharing"


def test_api_key_is_detected_as_secret() -> None:
    result = DataClassifier().classify("token DEMO_API_KEY_ABCDEF123456")
    assert any(item.entity_type == "API_KEY" for item in result.entities)


def test_financial_keyword_is_confidential() -> None:
    assert (
        DataClassifier().classify("quarterly revenue forecast").classification
        == ClassificationLevel.CONFIDENTIAL
    )


def test_redaction_removes_sensitive_value() -> None:
    classifier = DataClassifier()
    text = "SSN 000-12-3456"
    result = classifier.classify(text)
    assert "000-12-3456" not in classifier.redact(text, result)


def test_dlp_blocks_secrets_even_for_internal_use() -> None:
    classifier = DataClassifier()
    text = "client_secret=synthetic-secret-value"
    decision = DLPEngine().evaluate(
        content=text,
        classification=classifier.classify(text),
        external=False,
        roles=frozenset({Role.SECURITY_ADMIN}),
    )
    assert decision.decision == PolicyDecision.BLOCK
    assert decision.policy_id == "DLP-SECRET-001"


def test_dlp_blocks_highly_confidential_external_share() -> None:
    classifier = DataClassifier()
    text = "Synthetic SSN 000-12-3456"
    decision = DLPEngine().evaluate(
        content=text,
        classification=classifier.classify(text),
        external=True,
        roles=frozenset({Role.ANALYST}),
    )
    assert decision.decision == PolicyDecision.BLOCK
    assert decision.rule_matched == "block_highly_confidential_external_share"


def test_dlp_requires_approval_for_confidential_external_share() -> None:
    classifier = DataClassifier()
    text = "Contact customer@example.test"
    decision = DLPEngine().evaluate(
        content=text,
        classification=classifier.classify(text),
        external=True,
        roles=frozenset({Role.ANALYST}),
    )
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL
    assert decision.policy_id == "DLP-EXT-002"


def test_dlp_allows_authorized_internal_share() -> None:
    classifier = DataClassifier()
    text = "Internal team notes"
    decision = DLPEngine().evaluate(
        content=text,
        classification=classifier.classify(text),
        external=False,
        roles=frozenset({Role.USER}),
    )
    assert decision.decision == PolicyDecision.ALLOW


def test_dlp_decisions_are_deterministic() -> None:
    classifier = DataClassifier()
    engine = DLPEngine()
    result = classifier.classify("Contact customer@example.test")
    decisions = [
        engine.evaluate(
            content="Contact customer@example.test",
            classification=result,
            external=True,
            roles=frozenset({Role.ANALYST}),
        ).model_dump()
        for _ in range(5)
    ]
    assert all(item == decisions[0] for item in decisions)
