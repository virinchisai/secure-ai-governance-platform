package governance.dlp_test

import data.governance.dlp.decision

test_secret_has_priority if {
  result := decision with input as {
    "classification": "HIGHLY_CONFIDENTIAL",
    "external": true,
    "roles": ["analyst"],
    "entities": ["API_KEY"],
  }
  result.policy_id == "DLP-SECRET-001"
}

test_highly_confidential_external_is_blocked if {
  result := decision with input as {
    "classification": "HIGHLY_CONFIDENTIAL",
    "external": true,
    "roles": ["analyst"],
    "entities": ["US_SSN"],
  }
  result.decision == "BLOCK"
  result.policy_id == "DLP-EXT-001"
}

test_confidential_external_requires_approval if {
  result := decision with input as {
    "classification": "CONFIDENTIAL",
    "external": true,
    "roles": ["analyst"],
    "entities": ["EMAIL_ADDRESS"],
  }
  result.decision == "REQUIRE_APPROVAL"
}

test_internal_authorized_is_allowed if {
  result := decision with input as {
    "classification": "CONFIDENTIAL",
    "external": false,
    "roles": ["user"],
    "entities": [],
  }
  result.decision == "ALLOW"
}
