# Free Enterprise Integration Lab

The optional Compose overlay exercises real open-source integration boundaries without claiming a
production deployment or a live cloud connection.

## Components

| Component | Purpose | Status |
|---|---|---|
| Keycloak | Local OIDC issuer, JWKS, realm roles, workspace claim mapping | Integration-ready lab |
| Open Policy Agent | Rego DLP decision service | Local integration |
| Presidio Analyzer | PII entity augmentation | Local integration |
| PostgreSQL + pgvector | Durable approval/audit state and tenant-filtered retrieval | Local integration |
| OpenSearch + Dashboards | Searchable normalized security-event metadata | Local integration |
| Ollama | Optional model and embedding provider, run separately | Integration-ready |

No component is represented as a managed cloud service. The realm export contains no demo user or
credential; create local test identities in Keycloak and assign a governance role plus a
`workspace_id` user attribute.

## Start

```bash
docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up --build
```

Keycloak is exposed on `http://localhost:8080`, OPA on `http://localhost:8181`, Presidio on
`http://localhost:5001`, OpenSearch on `http://localhost:9200`, and Dashboards on
`http://localhost:5601`. The administrator password in the overlay is local-only and must be
changed before use outside an isolated developer machine.

Install the strict event index template before generating demo activity:

```bash
curl -X PUT http://localhost:9200/_index_template/governance-security-events \
  -H "Content-Type: application/json" \
  --data-binary @infra/opensearch/index-template.json
```

The overlay keeps `IDENTITY_MODE=local` so the existing demo login remains usable. To exercise OIDC
with an API client, create a local Keycloak identity, assign a governance role and `workspace_id`,
then set `IDENTITY_MODE=oidc`. In that mode the local password endpoint is intentionally disabled;
the browser authorization-code/PKCE flow is not implemented. The API validates the browser-visible
`http://localhost:8080/realms/governance` issuer while using the container-internal address only for
JWKS retrieval, preserving exact issuer checking instead of weakening it for container networking.

## Policy tests

```bash
docker run --rm -v "$PWD/policies:/policies:ro" \
  openpolicyagent/opa:1.10.1 test /policies
```

## Rollback

Stop the overlay and run only `docker compose up --build` to return to local identity,
classification, and policy providers. Set `PERSISTENCE_MODE=memory` and `RAG_MODE=local` for the
fully in-process runtime. Database schema rollback is explicit:

```bash
alembic downgrade -1
```

Back up durable data before any downgrade. Production hardening requires TLS, service
authentication, network policy, secret management, pinned image digests, backups, availability
testing, and a durable SIEM delivery queue.
