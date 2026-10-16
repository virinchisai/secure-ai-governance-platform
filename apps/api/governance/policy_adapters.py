from __future__ import annotations

import httpx

from .dlp import DLPEngine
from .domain import ClassificationResult, DLPDecision, PolicyDecision, Role


class PolicyProviderError(RuntimeError):
    pass


class OPADLPEngine(DLPEngine):
    """OPA-backed DLP engine. Network or schema failures deny the action."""

    def __init__(self, url: str, client: httpx.Client | None = None) -> None:
        self.url = url
        self.client = client or httpx.Client(timeout=5)

    def evaluate(
        self,
        *,
        content: str,
        classification: ClassificationResult,
        external: bool,
        roles: frozenset[Role],
    ) -> DLPDecision:
        del content
        request = {
            "input": {
                "classification": classification.classification.value,
                "external": external,
                "roles": sorted(role.value for role in roles),
                "entities": sorted({entity.entity_type for entity in classification.entities}),
            }
        }
        try:
            response = self.client.post(self.url, json=request)
            response.raise_for_status()
            result = response.json()["result"]
            return DLPDecision(
                decision=PolicyDecision(result["decision"]),
                policy_id=str(result["policy_id"]),
                rule_matched=str(result["rule_matched"]),
                reason=str(result["reason"]),
                affected_data=[str(item) for item in result.get("affected_data", [])],
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise PolicyProviderError("OPA policy evaluation failed closed") from exc
