# SecureBank — Bell-LaPadula confidentiality enforcement
#
# Encodes the four-level lattice declared in docs/01_SRD.md §6.6:
#   secret > confidential > restricted > unclassified
#
# Every authenticated request carries:
#   * input.subject.clearance ∈ {unclassified|restricted|confidential|secret}
#   * input.resource.classification (same domain)
#   * input.operation ∈ {read|write}
#
# Properties:
#   simple security ("no read up"): read allowed iff subject_lvl >= resource_lvl
#   *-property      ("no write down"): write allowed iff subject_lvl <= resource_lvl
#
# OPA returns `allow = true` only when BOTH the BLP check and the
# resource owner-check (in securebank_authz.rego) pass.

package securebank.bell_lapadula

import future.keywords.if
import future.keywords.in

# Ordered lattice — index = level value.
levels := ["unclassified", "restricted", "confidential", "secret"]

level_value(name) := i if {
    some i
    levels[i] == name
}

default allow_read := false
default allow_write := false

# Subject clearance value
subject_level := lv if {
    lv := level_value(input.subject.clearance)
} else := 0

resource_level := lv if {
    lv := level_value(input.resource.classification)
} else := 0

# Simple security property
allow_read if {
    input.operation == "read"
    subject_level >= resource_level
}

# *-property (star property)
allow_write if {
    input.operation == "write"
    subject_level <= resource_level
}

# Combined decision used by other policies.
allow if {
    input.operation == "read"
    allow_read
} else := true if {
    input.operation == "write"
    allow_write
} else := false

# Audit reason — what to log on a deny.
deny_reason := "BLP: subject 'unclassified' cannot read resource 'secret'" if {
    input.operation == "read"
    not allow_read
} else := "BLP: subject 'secret' cannot write to resource 'unclassified' (*-property)" if {
    input.operation == "write"
    not allow_write
}
