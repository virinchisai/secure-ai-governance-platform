# AXIS Skill Mapping

| Area | Evidence | Status |
|---|---|---|
| Secure agentic AI | Bounded workflow, trusted tool registry, pre-write checks | Implemented |
| AI governance | Explainable policy gateway and decision lineage | Implemented |
| Prompt injection defense | Retrieved-content boundary, detection, sanitization, regression tests | Implemented |
| Human-in-the-loop controls | Expiring, exact-argument, single-use approval | Implemented |
| RBAC | Four roles and server-side role-to-tool allowlist | Implemented |
| Least privilege | Unknown tools denied; user role cannot send; named DB queries | Implemented |
| Audit logging | Normalized tenant-scoped events, durable SQL sink, JSON logs | Implemented |
| DLP | Local deterministic rules plus fail-closed OPA policy adapter | Implemented; OPA optional |
| Sensitivity classification | Four levels, local rules, optional Presidio augmentation | Implemented; Presidio optional |
| Insider-risk concepts | Explainable threshold signals and score | Simulated behavioral analytics |
| Microsoft Graph | Provider contract and fail-closed configuration seam | Integration-ready; not live |
| Entra architecture | OIDC/JWKS validation and workspace/role claim mapping | Integration-ready; not tenant-connected |
| Purview concepts | Classification, labels, DLP policy concepts | Simulated; not Purview |
| PowerShell | Environment, Graph, config, events, audit export scripts | Implemented examples |
| Azure integration | Function-style handler and Logic App-style payload | Integration-ready template |
| SIEM/XDR integration | Normalized events and allowlisted OpenSearch adapter | Implemented locally; no cloud SIEM/XDR |
| Python | Typed FastAPI security services and tests | Implemented |
| TypeScript | Next.js governance console and typed API client | Implemented |
| API security | JWT, input limits, tenant checks, CORS, request IDs | Implemented locally |
| DevSecOps | CI, migrations, adversarial evals, OPA tests, CodeQL, Gitleaks, Semgrep, Trivy, SBOM | Implemented configuration |
