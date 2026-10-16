import { Pill, Shell } from "@/components/Shell";

const integrations = [
  ["Microsoft Entra ID", "OIDC identity provider adapter", "Integration-ready", "AZURE_TENANT_ID + app registration"],
  ["Microsoft Graph", "Files, users, messages and mail", "Integration-ready", "Tenant consent and Graph scopes"],
  ["Local Graph Simulator", "Synthetic documents and email", "Active", "No credentials"],
  ["Local Mock AI", "Deterministic summaries", "Active", "No network"],
  ["Ollama", "Optional local model inference", "Available", "Local Ollama endpoint"],
  ["Keycloak", "Local OIDC and JWKS validation lab", "Local option", "Enterprise Compose overlay"],
  ["Open Policy Agent", "Rego-backed DLP decisions", "Local option", "Enterprise Compose overlay"],
  ["Presidio", "PII analysis augmentation", "Local option", "Enterprise Compose overlay"],
  ["pgvector", "Tenant-filtered knowledge retrieval", "Local option", "PostgreSQL Compose service"],
  ["OpenSearch", "Normalized security event indexing", "Local option", "Enterprise Compose overlay"],
  ["Azure Workflows", "Security event forwarding templates", "Template", "Azure deployment configuration"],
];
export default function IntegrationsPage() { return <Shell title="Settings / Integrations" eyebrow="PROVIDER CONFIGURATION"><section className="page-intro"><p>Provider status is explicit. No external enterprise integration is represented as live.</p><Pill tone="good">Secure defaults</Pill></section><div className="integration-grid">{integrations.map(([name, detail, status, requirement]) => <section className="card integration" key={name}><div className="integration-icon">{name.slice(0, 2).toUpperCase()}</div><div><h2>{name}</h2><p>{detail}</p></div><Pill tone={status === "Active" ? "good" : status === "Integration-ready" ? "info" : "neutral"}>{status}</Pill><div className="requirement"><small>REQUIRES</small>{requirement}</div></section>)}</div></Shell>; }
