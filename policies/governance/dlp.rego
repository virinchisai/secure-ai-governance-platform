package governance.dlp

default decision := {
  "decision": "BLOCK",
  "policy_id": "DLP-DEFAULT-000",
  "rule_matched": "default_deny",
  "reason": "No allow policy matched.",
  "affected_data": [],
}

secret_entities := [entity | entity := input.entities[_]; entity in {"API_KEY", "SECRET"}]

has_secret if {
  count(secret_entities) > 0
}

decision := {
  "decision": "BLOCK",
  "policy_id": "DLP-SECRET-001",
  "rule_matched": "block_secrets_in_output",
  "reason": "Secrets may not be included in model or connector output.",
  "affected_data": secret_entities,
} if {
  has_secret
}

decision := {
  "decision": "BLOCK",
  "policy_id": "DLP-EXT-001",
  "rule_matched": "block_highly_confidential_external_share",
  "reason": "Highly confidential data cannot be shared externally.",
  "affected_data": input.entities,
} if {
  not has_secret
  input.external
  input.classification == "HIGHLY_CONFIDENTIAL"
}

decision := {
  "decision": "REQUIRE_APPROVAL",
  "policy_id": "DLP-EXT-002",
  "rule_matched": "approval_for_confidential_external_share",
  "reason": "Confidential external sharing requires compliance approval.",
  "affected_data": input.entities,
} if {
  not has_secret
  input.external
  input.classification == "CONFIDENTIAL"
}

decision := {
  "decision": "ALLOW",
  "policy_id": "DLP-INTERNAL-001",
  "rule_matched": "allow_authorized_internal_share",
  "reason": "The authenticated role may use this classification internally.",
  "affected_data": input.entities,
} if {
  not has_secret
  not input.external
  count(input.roles) > 0
}

decision := {
  "decision": "ALLOW",
  "policy_id": "DLP-EXT-003",
  "rule_matched": "allow_low_sensitivity_external_share",
  "reason": "No restricted data was detected.",
  "affected_data": input.entities,
} if {
  not has_secret
  input.external
  input.classification in {"PUBLIC", "INTERNAL"}
}
