# Microsoft Integration Architecture

## Current status

No Microsoft tenant or credentials are configured. M365-like files and email are supplied by
`LocalGraphSimulator`. Classification and DLP are local, Purview-style concepts only.

## Microsoft Entra ID

`IdentityProvider` defines the boundary. `LocalIdentityProvider` implements demo authentication;
`MicrosoftEntraProvider` deliberately rejects password authentication and reserves an OIDC
authorization-code flow. `OIDCTokenVerifier` implements RS256 signature/JWKS, issuer, audience,
expiry, subject, recognized-role, and workspace-claim validation and can be exercised with the local
Keycloak lab. The browser authorization-code/PKCE redirect flow is not implemented. A real Entra
integration still needs tenant allowlisting, group/app-role design, state/nonce handling in the
client flow, conditional-access validation, consent review, and operational key-rotation testing.

## Microsoft Graph

`GraphProvider` defines `list_users`, `list_files`, `read_file`, `list_messages`, `create_draft`, and
`send_message`. `MicrosoftGraphProvider` reads `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_SECRET`, then fails closed because tenant consent and HTTP execution have not been
configured.

Potential least-privilege application/delegated scopes depend on the chosen flow and resource model.
Candidates to review with a tenant administrator—not blanket recommendations—include:

- `User.Read.All` for directory user listing
- `Files.Read.All` or narrower site-selected access for document reads
- `Mail.Read` for message retrieval
- `Mail.ReadWrite` for drafts
- `Mail.Send` for sending

Production design should prefer delegated access where user intent matters, Sites.Selected or
resource-specific consent where possible, managed identity/workload federation over client secrets,
and explicit admin consent review. The PowerShell connectivity script only runs when the operator
provides environment credentials.

## Azure event workflows

`azure.py` transforms normalized audit events into an Azure Logic Apps-style envelope and exposes a
framework-neutral Azure Function-style handler. The JSON under `examples/workflows` is a deployment
template input, not a deployed Logic App. Authentication, endpoint, retry, dead-letter, and IaC are
required for a live deployment.
