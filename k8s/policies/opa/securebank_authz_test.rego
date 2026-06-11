package securebank.authz

test_customer_can_read_own_account {
  allow with input as {
    "subject": {"id": "u1", "roles": ["customer"], "mfa": false},
    "action": "read",
    "resource": {"type": "account", "owner": "u1"},
  }
}

test_customer_cannot_read_other_account {
  not allow with input as {
    "subject": {"id": "u1", "roles": ["customer"], "mfa": false},
    "action": "read",
    "resource": {"type": "account", "owner": "u2"},
  }
}

test_high_value_transfer_needs_mfa {
  not allow with input as {
    "subject": {"id": "u1", "roles": ["customer"], "mfa": false},
    "action": "transfer",
    "resource": {"amount": "50000"},
  }
}

test_high_value_transfer_with_mfa {
  allow with input as {
    "subject": {"id": "u1", "roles": ["customer"], "mfa": true},
    "action": "transfer",
    "resource": {"amount": "50000"},
  }
}
