"""Reasoner — generates plain-English explanations and triage decisions.

Two backends:

* `HeuristicReasoner`   — deterministic, no external API. Maps rule IDs
                          to canned narratives so the service works in
                          an air-gapped lab/exam environment.
* `AnthropicReasoner`   — calls the Claude API if `SB_LLM_API_KEY` is
                          set.  Prompts include strict guardrails so the
                          model never recommends destructive, irreversible
                          actions; only **suggests** a SOAR playbook ID.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


RULE_NARRATIVES: dict[str, dict[str, str]] = {
    "cred-stuffing": {
        "summary":  "Credential stuffing attempt detected.",
        "tactic":   "TA0006 Credential Access",
        "technique":"T1110.004 Brute Force: Credential Stuffing",
        "playbook": "PB-001-block-ip",
        "severity": "high",
        "rationale": (
            "Many failed logins from a single IP/user-agent against multiple "
            "accounts in a short window. The MFA gate and Argon2id hashing "
            "make individual cracking infeasible, but the IP itself should be "
            "blocked at the edge to reduce noise."
        ),
    },
    "jwt-anomaly": {
        "summary":  "Suspicious JWT verification pattern.",
        "tactic":   "TA0006 Credential Access",
        "technique":"T1550.001 Application Access Token",
        "playbook": "PB-002-jwt-rotation",
        "severity": "critical",
        "rationale": (
            "alg=none / alg confusion / jti replay attempts indicate an "
            "attacker is trying to forge tokens. Rotating the signing key "
            "(via Vault Transit) invalidates any stolen kid the attacker "
            "may already possess."
        ),
    },
    "memory-corruption": {
        "summary":  "Process in a SecureBank container crashed in a way consistent with memory corruption.",
        "tactic":   "TA0002 Execution",
        "technique":"T1203 Exploitation for Client Execution",
        "playbook": "PB-007-quarantine-pod",
        "severity": "critical",
        "rationale": (
            "Exit-code 139/134/11/6 inside our hardened distroless image is "
            "unexpected. Quarantine the pod immediately, then cordon the node "
            "so the scheduler does not place replacement traffic there until "
            "we have a forensic snapshot."
        ),
    },
    "container-escape": {
        "summary":  "Attempt to break out of the container sandbox.",
        "tactic":   "TA0004 Privilege Escalation",
        "technique":"T1611 Escape to Host",
        "playbook": "PB-007-quarantine-pod",
        "severity": "critical",
        "rationale": (
            "Process tried to access /proc/1, /host or invoke nsenter/mount. "
            "Even with `cap_drop:[ALL]` + readOnlyRootFilesystem this is a "
            "hostile signal."
        ),
    },
    "dns-exfiltration": {
        "summary":  "High-entropy DNS queries outside the allow-listed zones.",
        "tactic":   "TA0010 Exfiltration",
        "technique":"T1048.003 Exfiltration over DNS",
        "playbook": "PB-008-egress-quarantine",
        "severity": "high",
        "rationale": (
            "Subdomain length ≥30 chars and Shannon entropy ≥4.0 strongly "
            "suggests data is being chunked into DNS labels.  Cut egress "
            "from the affected namespace and capture pcap from the node."
        ),
    },
    "rbac-privilege-escalation": {
        "summary":  "Suspicious RBAC change granting admin-equivalent rights.",
        "tactic":   "TA0004 Privilege Escalation",
        "technique":"T1098.001 Additional Cloud Credentials",
        "playbook": "PB-005-revoke-rbac",
        "severity": "critical",
        "rationale": (
            "A RoleBinding/ClusterRoleBinding pointing at cluster-admin / admin "
            "/ edit was created by a non-system actor.  Roll the binding back "
            "and revoke the SA token."
        ),
    },
    "fraud-ml": {
        "summary":  "Transaction flagged as fraudulent by the ML model.",
        "tactic":   "TA0040 Impact",
        "technique":"T1565 Data Manipulation (financial)",
        "playbook": "PB-003-freeze-account",
        "severity": "high",
        "rationale": (
            "Isolation-forest score > 0.85 AND the transaction is over the "
            "step-up threshold OR the recipient is novel for this user. "
            "Freezing the source account preserves funds; user can call "
            "support to lift the freeze after KYC verification."
        ),
    },
}


@dataclass
class Explanation:
    rule_id: str
    summary: str
    tactic: str
    technique: str
    severity: str
    suggested_playbook: str
    rationale: str
    backend: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class Reasoner(Protocol):
    def explain(self, rule_id: str, context: dict) -> Explanation: ...


# ----------------------------------------------------------- heuristic

class HeuristicReasoner:
    backend = "heuristic"

    def explain(self, rule_id: str, context: dict) -> Explanation:
        n = RULE_NARRATIVES.get(rule_id)
        if not n:
            return Explanation(
                rule_id=rule_id, summary=f"Unknown rule '{rule_id}'.",
                tactic="—", technique="—", severity="medium",
                suggested_playbook="PB-000-manual",
                rationale="No narrative registered. Triage manually.",
                backend=self.backend,
            )
        # Mix in any contextual facts the caller passed (pod, user, ip…)
        rationale = n["rationale"]
        extras = [f"{k}={v}" for k, v in context.items() if v]
        if extras:
            rationale += "\n\nContext: " + ", ".join(extras)
        return Explanation(
            rule_id=rule_id,
            summary=n["summary"], tactic=n["tactic"], technique=n["technique"],
            severity=n["severity"], suggested_playbook=n["playbook"],
            rationale=rationale, backend=self.backend,
        )


# ----------------------------------------------------------- Anthropic (optional)

class AnthropicReasoner:
    backend = "anthropic"

    SYSTEM = (
        "You are SecureBank's AI security analyst. You explain SIEM/Falco/ML "
        "alerts to engineers. You MUST: (1) be concise, (2) cite MITRE "
        "tactic + technique IDs, (3) recommend at most ONE SOAR playbook by "
        "its PB-### identifier from the list below, (4) never recommend "
        "destructive actions outside the SOAR catalog. Output JSON with keys: "
        "summary, tactic, technique, severity (info|low|medium|high|critical), "
        "suggested_playbook (PB-###), rationale (≤120 words)."
    )

    def __init__(self, api_key: str, model: str) -> None:
        import anthropic  # local import — optional dep
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model  = model

    def explain(self, rule_id: str, context: dict) -> Explanation:
        prompt = (
            f"Rule ID: {rule_id}\nContext: {context}\n"
            "Known playbooks: PB-001 block-ip, PB-002 jwt-rotation, "
            "PB-003 freeze-account, PB-004 cordon-node, PB-005 revoke-rbac, "
            "PB-006 kill-sessions, PB-007 quarantine-pod, PB-008 egress-quarantine."
        )
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=400,
            system=self.SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        import json
        try:
            data = json.loads(msg.content[0].text)
        except Exception:
            data = {}
        return Explanation(
            rule_id=rule_id,
            summary=data.get("summary", "AI explanation unavailable"),
            tactic=data.get("tactic", "—"),
            technique=data.get("technique", "—"),
            severity=data.get("severity", "medium"),
            suggested_playbook=data.get("suggested_playbook", "PB-000-manual"),
            rationale=data.get("rationale", ""),
            backend=self.backend,
        )


def build_reasoner(provider: str, api_key: str | None, model: str) -> Reasoner:
    if provider == "anthropic" and api_key:
        return AnthropicReasoner(api_key, model)
    return HeuristicReasoner()
