# Architecture

## Trust boundaries

1. **Client to API:** the browser is untrusted. Authentication, role checks, workspace resolution,
   policy, and approvals are server-owned.
2. **Identity to resource:** token workspace claims are compared with resource workspace ownership.
   A document lookup includes workspace identity; “not found” avoids cross-tenant enumeration.
3. **Connector to retrieved content:** connector metadata is trusted only after adapter validation;
   document text is always untrusted and cannot become a system instruction.
4. **AI provider to policy:** provider output is untrusted content. It is classified and inspected;
   it cannot authorize itself or invoke a tool.
5. **Approval to action:** only the canonical approved action and arguments can consume the grant.
6. **Application to telemetry:** raw sensitive payloads are excluded from audit and metrics.

## Module ownership

| Module | Owns |
|---|---|
| `identity.py` | PBKDF2 local authentication, identity contracts, JWT issue/verify |
| `rbac.py` | role-to-tool allowlist and workspace boundary |
| `classification.py` | entity detection, levels, labels, redaction |
| `dlp.py` | deterministic ordered sharing and content policy |
| `injection.py` | suspicious instruction detection and content isolation |
| `approvals.py` | expiry, decision state, immutable action digest, single-use consume |
| `agent.py` | bounded orchestration and final connector enforcement |
| `connectors.py` | Graph contract, local simulator, named-query database |
| `audit.py` / `risk.py` | normalized events and explainable behavior signals |
| `cache.py` | authorization-scoped cache key and sensitive bypass |
| `azure.py` | deployment-neutral Azure workflow payload mapping |

## Core request sequence

1. Verify JWT signature, issuer, expiration, roles, and workspace.
2. Validate recipient and determine internal/external destination.
3. Authorize `get_document`; read using the workspace-scoped connector method.
4. Inspect untrusted retrieved text and remove instruction-like spans from AI input.
5. Classify sources, summarize with the configured bounded provider, classify output.
6. Evaluate ordered DLP and emit policy evidence.
7. Block; redact and reevaluate; request exact-action approval; or proceed.
8. Immediately before a write, reauthorize, validate arguments, reclassify body, and reevaluate DLP.
9. Invoke the connector and emit normalized audit/risk evidence.

## Persistence

`persistence.py` provides a SQLAlchemy audit model and sink. The default runtime deliberately uses an
in-memory sink for zero-setup tests and demos. PostgreSQL is present in Compose as the production-like
database target, but durable repositories and migrations remain a stated hardening gap.
