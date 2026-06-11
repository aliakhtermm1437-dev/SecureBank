# SecureBank — Clark-Wilson integrity enforcement
#
# Validates the (user, TP, CDI) triple required by Clark-Wilson before
# allowing any transformation procedure to execute.  Pairs with the
# database-side `transfer_funds()` SERIALIZABLE stored procedure and the
# append-only audit chain described in docs/01_SRD.md §6.6.

package securebank.clark_wilson

import future.keywords.if
import future.keywords.in

# Whitelisted transformation procedures.
allowed_tps := {
    "transfer_funds",
    "freeze_account",
    "unfreeze_account",
    "open_account",
    "close_account",
    "rotate_jwt_keys",
}

# Subjects with permission to invoke each TP.
tp_roles := {
    "transfer_funds":   {"customer", "teller"},
    "freeze_account":   {"soar", "fraud-officer"},
    "unfreeze_account": {"branch-manager", "compliance"},
    "open_account":     {"customer", "teller"},
    "close_account":    {"customer", "compliance"},
    "rotate_jwt_keys":  {"soar", "security-admin"},
}

# CDI ownership — for transfers, the caller must own the source CDI.
# For admin TPs (freeze/unfreeze), the caller's role must include
# fraud-officer or compliance.

default allow := false
default deny_reason := ""

allow if {
    input.tp in allowed_tps
    input.role in tp_roles[input.tp]
    tp_specific_check
    separation_of_duty_ok
}

# --- TP-specific checks -----------------------------------------------

tp_specific_check if {
    input.tp == "transfer_funds"
    input.cdi.owner == input.subject.sub
}

tp_specific_check if {
    input.tp == "freeze_account"
    # the actor must NOT be the owner of the account being frozen
    input.cdi.owner != input.subject.sub
}

tp_specific_check if {
    input.tp in {"open_account", "close_account"}
    input.cdi.owner == input.subject.sub
}

tp_specific_check if {
    input.tp in {"unfreeze_account", "rotate_jwt_keys"}
    # No CDI-ownership constraint for admin operations.
    true
}

# --- Separation of Duty -----------------------------------------------
# High-value transfers require approver != initiator.

separation_of_duty_ok if {
    input.tp == "transfer_funds"
    input.amount_minor < 100000000   # < 1,000,000.00 PKR in paisa
}

separation_of_duty_ok if {
    input.tp == "transfer_funds"
    input.amount_minor >= 100000000
    input.approver != input.subject.sub
    input.approver_role in {"branch-manager", "compliance"}
}

separation_of_duty_ok if {
    input.tp != "transfer_funds"
    true
}

# --- Decision metadata -----------------------------------------------

deny_reason := sprintf("TP %q not whitelisted", [input.tp]) if {
    not input.tp in allowed_tps
} else := sprintf("role %q not authorized for TP %q", [input.role, input.tp]) if {
    not input.role in tp_roles[input.tp]
} else := "Clark-Wilson: CDI ownership / role check failed" if {
    not tp_specific_check
} else := "Clark-Wilson: separation-of-duty (4-eyes) required for this amount" if {
    not separation_of_duty_ok
}
