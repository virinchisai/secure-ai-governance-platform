# Security Policy

## Supported version

This portfolio reference implementation supports the current `main` branch. It is not a hosted
service and has not undergone an independent penetration test.

## Reporting a vulnerability

Do not open a public issue containing exploit details or secrets. Use GitHub private vulnerability
reporting when enabled. Include the affected component, reproduction steps, impact, and a suggested
mitigation. No bounty program is represented.

## Secure deployment expectations

- Replace the local JWT secret and demo credentials; use a managed OIDC provider.
- Terminate TLS at a trusted ingress and restrict CORS to the deployed web origin.
- Store connector credentials in a managed secret store and rotate them.
- Replace in-memory approvals and risk state with transactional durable storage.
- Configure database encryption, backup, retention, row-level tenant controls, and migrations.
- Forward audit events through an authenticated, retrying, integrity-protected pipeline.
- Review DLP rules with legal, privacy, and compliance owners before use.
- Pin container images by digest and scan built artifacts.

Never submit real personal data, customer data, or credentials to the demo fixtures.
