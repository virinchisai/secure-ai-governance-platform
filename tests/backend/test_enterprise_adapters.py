import httpx
import jwt
import pytest

from apps.api.governance.classification import DataClassifier
from apps.api.governance.classifier_adapters import ClassifierProviderError, PresidioClassifier
from apps.api.governance.domain import ClassificationLevel, PolicyDecision, Role
from apps.api.governance.identity import AuthenticationError, OIDCTokenVerifier
from apps.api.governance.policy_adapters import OPADLPEngine, PolicyProviderError


def test_oidc_claims_map_workspace_and_known_roles() -> None:
    context = OIDCTokenVerifier._context_from_claims(
        {"sub": "subject-1", "workspace_id": "workspace-a", "realm_access": {"roles": ["analyst"]}}
    )
    assert context.workspace_id == "workspace-a"
    assert context.roles == frozenset({Role.ANALYST})


def test_oidc_claims_require_workspace() -> None:
    with pytest.raises(AuthenticationError, match="workspace"):
        OIDCTokenVerifier._context_from_claims({"sub": "subject-1", "roles": ["analyst"]})


def test_oidc_verify_enforces_issuer_audience_and_required_claims(monkeypatch) -> None:
    verifier = OIDCTokenVerifier(
        "https://issuer.example/realm",
        "governance-api",
        "http://identity-internal/certs",
    )

    class SigningKey:
        key = "public-key"

    class JWKS:
        @staticmethod
        def get_signing_key_from_jwt(token: str) -> SigningKey:
            assert token == "signed-token"
            return SigningKey()

    verifier._jwks = JWKS()

    def decode(token, key, **kwargs):
        assert token == "signed-token"
        assert key == "public-key"
        assert kwargs["algorithms"] == ["RS256"]
        assert kwargs["issuer"] == "https://issuer.example/realm"
        assert kwargs["audience"] == "governance-api"
        assert kwargs["options"]["require"] == ["exp", "iat", "sub"]
        return {"sub": "subject-1", "workspace_id": "workspace-a", "roles": ["analyst"]}

    monkeypatch.setattr(jwt, "decode", decode)

    assert verifier.verify("signed-token").roles == frozenset({Role.ANALYST})


def test_oidc_invalid_signature_is_rejected(monkeypatch) -> None:
    verifier = OIDCTokenVerifier("https://issuer.example", "governance-api")

    class JWKS:
        @staticmethod
        def get_signing_key_from_jwt(_token: str):
            raise jwt.InvalidSignatureError

    verifier._jwks = JWKS()
    with pytest.raises(AuthenticationError, match="Invalid or expired"):
        verifier.verify("invalid-token")


def test_opa_decision_is_machine_readable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/decision")
        return httpx.Response(
            200,
            json={
                "result": {
                    "decision": "REQUIRE_APPROVAL",
                    "policy_id": "DLP-EXT-002",
                    "rule_matched": "approval_for_confidential_external_share",
                    "reason": "approval required",
                    "affected_data": ["EMAIL"],
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = OPADLPEngine("http://opa/v1/data/governance/dlp/decision", client).evaluate(
        content="ignored",
        classification=DataClassifier().classify("user@example.test"),
        external=True,
        roles=frozenset({Role.ANALYST}),
    )
    assert result.decision == PolicyDecision.REQUIRE_APPROVAL
    assert result.policy_id == "DLP-EXT-002"


def test_opa_failure_is_fail_closed() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with pytest.raises(PolicyProviderError, match="failed closed"):
        OPADLPEngine("http://opa/decision", client).evaluate(
            content="safe",
            classification=DataClassifier().classify("safe"),
            external=False,
            roles=frozenset({Role.ANALYST}),
        )


def test_presidio_entities_raise_classification() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json=[{"entity_type": "US_SSN", "start": 5, "end": 16, "score": 0.99}],
            )
        )
    )
    result = PresidioClassifier("http://presidio", client).classify("data synthetic-id")
    assert result.classification == ClassificationLevel.HIGHLY_CONFIDENTIAL
    assert any(entity.entity_type == "US_SSN" for entity in result.entities)


def test_presidio_unavailable_is_explicit() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    with pytest.raises(ClassifierProviderError, match="unavailable"):
        PresidioClassifier("http://presidio", client).classify("safe")
