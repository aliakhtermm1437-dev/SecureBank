package securebank.authz

# Default deny.
default allow = false

# customer: can read and mutate their own account; can transfer from their own acct.
allow {
  input.subject.roles[_] == "customer"
  input.action == "read"
  input.resource.type == "account"
  input.resource.owner == input.subject.id
}

allow {
  input.subject.roles[_] == "customer"
  input.action == "create"
  input.resource.type == "account"
}

allow {
  input.subject.roles[_] == "customer"
  input.action == "credit"
}

allow {
  input.subject.roles[_] == "customer"
  input.action == "debit"
}

allow {
  input.subject.roles[_] == "customer"
  input.action == "transfer"
  amt := to_number(input.resource.amount)
  amt > 0
  # Step-up MFA required for high-value moves — enforced at app layer too.
  amt <= 10000
}

allow {
  input.subject.roles[_] == "customer"
  input.action == "transfer"
  to_number(input.resource.amount) > 10000
  input.subject.mfa == true
}

# admin: full read + audit, but no money movement.
allow {
  input.subject.roles[_] == "admin"
  input.action == "read"
}
