# Threat Model

Scope: the local platform and its integration boundaries. Validation names correspond to tests under
`tests/backend`. Residual risk remains because this is a reference implementation, not a certified
production control.

| Threat | Attack scenario | Impact | Mitigation | Validation / test |
|---|---|---|---|---|
| Prompt injection | User asks the model to ignore policy or assume admin | Unauthorized action | Roles come only from verified JWT; suspicious instructions are detected; model cannot execute tools | `test_prompt_injection_patterns_detected`, `test_prompt_injection_does_not_change_user_roles` |
| Indirect prompt injection | Retrieved supplier file says to upload all files | Exfiltration / tool misuse | Retrieved text is untrusted, inspected, scrubbed, and never becomes policy; connector checks remain authoritative | `test_prompt_injection_is_contained_and_audited` |
| Data exfiltration | Highly confidential record is emailed externally | Privacy or regulatory harm | Source and output classification, external-recipient determination, ordered DLP block | `test_sensitive_external_share_is_blocked`, API equivalent |
| Confused deputy | User leverages an agent's connector privileges | Action exceeds user privileges | Every tool call checks current user role and tenant; no model-held superuser identity | `test_basic_user_cannot_send_email_tool` |
| Excessive agency | Model invents a shell or admin tool | Code execution / destructive action | Bounded workflow and static allowlist; unknown tool names fail closed | `test_model_cannot_select_unknown_tool` |
| Cross-tenant access | Tenant A requests Tenant B document ID | Confidentiality breach | Workspace-scoped lookup plus explicit workspace authorization; non-enumerating failure | `test_cross_tenant_authorization_is_blocked`, `test_cross_tenant_document_is_not_retrievable` |
| Privilege escalation | Prompt claims “You are now administrator” | Administrative access | JWT role is immutable application context; text is never parsed into authorization | Prompt-injection role regression test |
| Malicious tool arguments | Recipient or query contains attacker-controlled syntax | Exfiltration / injection | Email syntax and length validation, named database queries, canonical approval arguments | `test_safe_database_rejects_arbitrary_query`, recipient validation path |
| Approval replay | Previously approved write is resubmitted | Repeated unauthorized write | Approval atomically transitions to consumed and is single-use | `test_approval_is_single_use` |
| Approval mutation | Recipient/body/document is changed after approval | Approval bypass | HMAC of exact canonical action and arguments; constant-time compare | `test_modified_action_invalidates_approval` |
| Sensitive cache leakage | Same prompt in another tenant returns cached data | Cross-user/tenant exposure | Cache key includes workspace, user, authorization context, and prompt; sensitive bypass and expiry | cache isolation, bypass, and expiry tests |
| Credential exposure | Secret appears in a document, output, repo, or log | Account compromise | Secret/API-key detection blocks output; env-only provider config; ignored env files; logs omit content | `test_api_key_is_detected_as_secret`, `test_dlp_blocks_secrets_even_for_internal_use` |
| Insecure logging | Raw PII is emitted to SIEM | Secondary data breach | Audit schema accepts metadata/evidence, not payload; masked entity values | event schema review and audit regression |
| Insider abuse | User repeatedly enumerates or exports sensitive files | Data loss | Explainable bulk, blocked-export, share, auth failure, sensitive enumeration, privilege, and time rules | insider-risk signal tests |

## Assets

Workspace documents, email actions, identities/roles, policy definitions, approvals, audit evidence,
connector credentials, and cached model responses.

## Assumptions

The host and local developer account are trusted for the demo. TLS and perimeter controls are out of
scope locally. Synthetic fixtures contain no real personal or customer data. Live connector adapters
must undergo a new threat review when enabled.
