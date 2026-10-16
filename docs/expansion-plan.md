# Free and Open-Source Expansion Plan

## Acceptance

- Existing local mode remains runnable without Docker or network services.
- Compose can opt into PostgreSQL-backed audit and approval state.
- OIDC tokens can be verified against a configured JWKS issuer; local identity remains the fallback.
- OPA and Presidio adapters fail closed or fall back only when explicitly configured to do so.
- Retrieval always filters by workspace before ranking or returning chunks.
- Security events can be normalized for OpenSearch without including raw document content.
- Adversarial fixtures produce reproducible pass/fail results rather than invented metrics.
- CI defines secret, dependency, static-analysis, container, IaC, SBOM, and dynamic API checks.

## Migration sequence

1. Expand: add repository protocols, SQL tables, and an initial idempotent migration.
2. Dual mode: keep in-memory services as the default; opt into SQL with `PERSISTENCE_MODE=database`.
3. Verify: run the same approval and audit contract tests against both implementations.
4. Contract later: removing in-memory mode is explicitly out of scope for this release.

## Rollback

Set `PERSISTENCE_MODE=memory`, `IDENTITY_MODE=local`, `POLICY_PROVIDER=local`, and
`CLASSIFIER_PROVIDER=local`. No destructive schema rollback is required; added tables can remain.

