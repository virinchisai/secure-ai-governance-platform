# AXIS Skill Mapping

| Area | Evidence | Status |
|---|---|---|
| Secure agentic AI | Bounded workflow, trusted tool registry, pre-write checks | Implemented |
| AI governance | Explainable policy gateway and decision lineage | Implemented |
| Prompt injection defense | Retrieved-content boundary, detection, sanitization, regression tests | Implemented |
| Human-in-the-loop controls | Expiring, exact-argument, single-use approval | Implemented |
| RBAC | Four roles and server-side role-to-tool allowlist | Implemented |
| Least privilege | Unknown tools denied; user role cannot send; named DB queries | Implemented |
| Audit logging | Normalized tenant-scoped events and JSON structured logs | Implemented locally |
| DLP | Ordered deterministic block/redact/approval/allow rules | Implemented locally |
| Sensitivity classification | Four levels, local labels, entity evidence | Implemented locally |
| Insider-risk concepts | Explainable threshold signals and score | Simulated behavioral analytics |
| Microsoft Graph | Provider contract and fail-closed configuration seam | Integration-ready; not live |
| Entra architecture | Identity contract and OIDC design boundary | Integration-ready; not live |
| Purview concepts | Classification, labels, DLP policy concepts | Simulated; not Purview |
| PowerShell | Environment, Graph, config, events, audit export scripts | Implemented examples |
| Azure integration | Function-style handler and Logic App-style payload | Integration-ready template |
| SIEM/XDR integration | Normalized events and forwarding callback | Integration-ready; no live SIEM/XDR |
| Python | Typed FastAPI security services and tests | Implemented |
| TypeScript | Next.js governance console and typed API client | Implemented |
| API security | JWT, input limits, tenant checks, CORS, request IDs | Implemented locally |
| DevSecOps | CI, Ruff, mypy, pytest, Bandit, npm audit, CodeQL, Dependabot | Implemented configuration |
