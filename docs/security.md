# Security Design

## Authorization

Tool permissions are allowlisted. Unknown tool names fail closed. The `user` role cannot send email;
`analyst`, `security_admin`, and `compliance_admin` can send only after policy checks. Compliance or
security admin is required to decide approvals. Resource access also requires the same workspace.

## Prompt and agent safety

System policy lives in code. Retrieved documents are never concatenated into privileged system
instructions. Known override, escalation, exfiltration, secret-request, and tool-override phrases are
detected and removed before summarization; the detection emits an event. This is defense in depth,
not a guarantee that pattern detection recognizes every adversarial string. Final authorization and
DLP remain effective even if detection misses.

## Data protection

Entity results expose masked values. Audit data records entity type and policy evidence rather than
raw content. Sensitive cache entries can be bypassed and all keys bind workspace, user, role context,
and prompt. Secrets always produce a block decision.

## Approval integrity

Canonical JSON uses sorted keys and compact separators. An HMAC-SHA-256 digest binds action and all
arguments using a server-held key. Comparison is constant-time. Status transitions allow pending to
approved/rejected and approved to consumed; expired, rejected, and consumed grants cannot execute.

## Secure defaults

Providers default to `local` Graph and `mock` AI. Missing Microsoft credentials fail closed.
Arbitrary SQL is rejected in favor of named queries. CORS allows only the local UI origin, response
request IDs are bounded, and containers run as non-root users.
