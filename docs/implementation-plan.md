# Implementation Plan

## Acceptance outcomes

1. A local user can authenticate, retrieve only same-workspace documents, and request a summary.
2. Every tool call is authorized server-side; retrieved text is always treated as untrusted data.
3. Classification, secret/PII detection, deterministic DLP, immutable approvals, risk signals,
   audit records, and SIEM events protect the external-email workflow.
4. Local simulators make the full demo runnable without cloud credentials. Cloud adapters fail
   closed when configuration is absent and are documented as integration-ready.
5. Backend security regression tests (at least 25), lint, type checks, frontend lint/type checks,
   and CI security scans pass.

## Architecture decisions

- The policy gateway, not the model, owns authorization and tool execution.
- Tenant/workspace identity is carried in signed tokens and rechecked at every resource boundary.
- Classification and DLP are deterministic local controls. Model output is inspected again before use.
- Approval grants are single-use, expiring, and bound to a canonical hash of action arguments.
- Audit and SIEM schemas exclude raw sensitive payloads; affected entity types are recorded instead.
- SQLite is the zero-setup local database; PostgreSQL is the Docker Compose target.
- Mock AI and Graph implementations are the default. External providers require explicit configuration.

## Phases and proof

1. Foundation: schemas, configuration, identity, connector contracts, persistence.
2. Security core: classification, DLP, prompt-injection defense, approval, risk, audit, cache.
3. Agent flow: bounded tool registry and end-to-end external-sharing scenario.
4. API and demo data: authenticated routes and reproducible synthetic fixtures.
5. Frontend: enterprise pages exposing decisions, traces, approvals, and events.
6. Integration assets: Graph/Entra/Azure interfaces, PowerShell, workflows, SIEM samples.
7. Documentation and CI: threat model, security docs, skill mapping, workflows.
8. Verification: backend tests, Ruff, mypy, frontend lint/typecheck/build, security review.

## Explicit non-goals

- No claim of live cloud AI, Microsoft, Azure, SIEM, or production integrations.
- No autonomous arbitrary tool selection, unrestricted SQL, or model-mediated authorization.
- No production-grade behavioral ML; risk analytics are explainable local rules.
- No raw sensitive content in logs, metrics, or cache identifiers.
