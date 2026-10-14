# Classification and DLP

This is a **Purview-style classification and DLP simulation** implemented locally. It does not call
or represent Microsoft Purview.

## Classification

The classifier assigns the highest level supported by detected rules:

| Detection | Level | Notes |
|---|---|---|
| explicit public marker | PUBLIC | only when no higher rule matches |
| baseline content | INTERNAL | secure baseline |
| email, phone, customer ID, financial keyword | CONFIDENTIAL | external share requires approval |
| SSN, payment-card-like, API key, credential-like secret | HIGHLY_CONFIDENTIAL | external share blocked |

Confidence expresses rule confidence, not measured ML accuracy. No accuracy metric is claimed.

## Ordered DLP policy

1. `DLP-SECRET-001`: block detected secret/API-key output.
2. `DLP-EXT-001`: block highly confidential external sharing.
3. `DLP-PII-001`: redact high-risk PII when a higher block does not apply.
4. `DLP-EXT-002`: require approval for confidential external sharing.
5. `DLP-INTERNAL-001`: allow internal use for authorized roles.
6. `DLP-EXT-003`: allow low-sensitivity external sharing.
7. `DLP-DEFAULT-000`: deny if no allow rule matches.

Every result includes decision, policy ID, matching rule, reason, and affected entity types.
