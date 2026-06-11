"""SOAR playbooks.

Each playbook is a small, idempotent function that takes the typed
offense and a `Context` (Redis + K8s + Auth client) and returns an
``ActionResult``.  Playbooks NEVER modify state on their own — they
delegate to the platform's existing APIs so every change is audit-logged
through the usual paths.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from kubernetes import client as k8s_client

logger = logging.getLogger(__name__)


@dataclass
class Offense:
    """Typed view of a QRadar offense / Falco alert / Loki match."""

    offense_id: str
    source: str            # "qradar" | "falco" | "loki" | "ml"
    rule_id: str
    severity: str          # info | low | medium | high | critical
    raw: dict[str, Any]    # original payload
    namespace: str | None = None
    pod: str | None = None
    user_sub: str | None = None
    src_ip: str | None = None
    account_id: str | None = None

    @property
    def dedupe_key(self) -> str:
        h = hashlib.sha256()
        for piece in (self.source, self.rule_id, self.namespace or "",
                      self.pod or "", self.user_sub or "",
                      self.src_ip or "", self.account_id or ""):
            h.update(piece.encode())
        return h.hexdigest()[:32]


@dataclass
class ActionResult:
    playbook: str
    actions: list[str] = field(default_factory=list)
    success: bool = True
    error: str | None = None


@dataclass
class Context:
    redis: Any
    k8s_core: k8s_client.CoreV1Api
    k8s_apps: k8s_client.AppsV1Api
    k8s_net:  k8s_client.NetworkingV1Api
    k8s_rbac: k8s_client.RbacAuthorizationV1Api
    http:     httpx.AsyncClient
    auth_url: str
    account_url: str
    dry_run:  bool


# ---------------------------------------------------------------- helpers

async def _post(ctx: Context, url: str, json: dict) -> None:
    if ctx.dry_run:
        logger.info("DRY-RUN POST %s payload=%s", url, json)
        return
    r = await ctx.http.post(url, json=json, timeout=10.0)
    r.raise_for_status()


def _ns(off: Offense) -> str:
    return off.namespace or "securebank-app"


# ---------------------------------------------------------------- playbooks

async def pb_001_block_ip(off: Offense, ctx: Context) -> ActionResult:
    """Block offending source IP at the API gateway for 60 minutes."""
    res = ActionResult(playbook="PB-001-block-ip")
    if not off.src_ip:
        res.success = False
        res.error = "no src_ip in offense"
        return res
    ttl = 60 * 60
    key = f"gw:deny:ip:{off.src_ip}"
    if not ctx.dry_run:
        await ctx.redis.setex(key, ttl, off.offense_id)
    res.actions.append(f"redis set {key} ttl={ttl}")
    return res


async def pb_002_jwt_rotation(off: Offense, ctx: Context) -> ActionResult:
    """Force a JWT signing-key rotation in the auth-service."""
    res = ActionResult(playbook="PB-002-jwt-rotation")
    await _post(ctx, f"{ctx.auth_url}/internal/keys/rotate",
                {"reason": off.rule_id, "offense_id": off.offense_id})
    res.actions.append("called /internal/keys/rotate")
    return res


async def pb_003_freeze_account(off: Offense, ctx: Context) -> ActionResult:
    """Mark an account as `frozen` so no debits can occur."""
    res = ActionResult(playbook="PB-003-freeze-account")
    if not off.account_id:
        res.success = False
        res.error = "no account_id"
        return res
    await _post(ctx, f"{ctx.account_url}/internal/accounts/{off.account_id}/freeze",
                {"reason": off.rule_id, "offense_id": off.offense_id})
    res.actions.append(f"froze account {off.account_id}")
    return res


async def pb_004_cordon_node(off: Offense, ctx: Context) -> ActionResult:
    """Cordon the node that hosts the affected pod."""
    res = ActionResult(playbook="PB-004-cordon-node")
    if not off.pod or not off.namespace:
        res.success = False
        res.error = "no pod/namespace"
        return res
    try:
        pod = ctx.k8s_core.read_namespaced_pod(off.pod, off.namespace)
        node_name = pod.spec.node_name
    except Exception as e:  # noqa: BLE001
        res.success = False
        res.error = f"could not resolve pod: {e}"
        return res
    if not ctx.dry_run:
        body = {"spec": {"unschedulable": True}}
        ctx.k8s_core.patch_node(node_name, body)
    res.actions.append(f"cordoned node {node_name}")
    return res


async def pb_005_revoke_rbac(off: Offense, ctx: Context) -> ActionResult:
    """Undo a privilege-escalation RoleBinding."""
    res = ActionResult(playbook="PB-005-revoke-rbac")
    binding = off.raw.get("binding_name")
    ns      = off.raw.get("namespace") or "default"
    if not binding:
        res.success = False
        res.error = "no binding name"
        return res
    if not ctx.dry_run:
        try:
            ctx.k8s_rbac.delete_namespaced_role_binding(binding, ns)
        except Exception:
            ctx.k8s_rbac.delete_cluster_role_binding(binding)
    res.actions.append(f"deleted binding {ns}/{binding}")
    return res


async def pb_006_kill_session_family(off: Offense, ctx: Context) -> ActionResult:
    """Invalidate every active session of the targeted user (sub)."""
    res = ActionResult(playbook="PB-006-kill-sessions")
    if not off.user_sub:
        res.success = False; res.error = "no user_sub"; return res
    await _post(ctx, f"{ctx.auth_url}/internal/sessions/revoke",
                {"sub": off.user_sub, "reason": off.rule_id})
    res.actions.append(f"revoked sessions for sub={off.user_sub}")
    return res


async def pb_007_quarantine_pod(off: Offense, ctx: Context) -> ActionResult:
    """Label the offending pod for quarantine and detach it via NetworkPolicy."""
    res = ActionResult(playbook="PB-007-quarantine-pod")
    if not off.pod or not off.namespace:
        res.success = False; res.error = "no pod/ns"; return res
    if not ctx.dry_run:
        body = {"metadata": {"labels": {"securebank.io/quarantine": "true"}}}
        ctx.k8s_core.patch_namespaced_pod(off.pod, off.namespace, body)
    res.actions.append(f"labelled {off.namespace}/{off.pod} quarantine=true")
    return res


async def pb_008_egress_quarantine(off: Offense, ctx: Context) -> ActionResult:
    """Apply an emergency egress-deny NetworkPolicy to the namespace."""
    res = ActionResult(playbook="PB-008-egress-quarantine")
    ns = _ns(off)
    np = k8s_client.V1NetworkPolicy(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=k8s_client.V1ObjectMeta(name="deny-egress-emergency", namespace=ns),
        spec=k8s_client.V1NetworkPolicySpec(
            pod_selector=k8s_client.V1LabelSelector(),
            policy_types=["Egress"],
            egress=[]),
    )
    if not ctx.dry_run:
        try:
            ctx.k8s_net.create_namespaced_network_policy(ns, np)
        except k8s_client.exceptions.ApiException as e:
            if e.status != 409:           # already exists is fine
                raise
    res.actions.append(f"deny-egress-emergency applied to {ns}")
    return res


# Rule → playbook(s)
DISPATCH: dict[str, list] = {
    "cred-stuffing":          [pb_001_block_ip, pb_006_kill_session_family],
    "jwt-anomaly":            [pb_002_jwt_rotation, pb_001_block_ip],
    "memory-corruption":      [pb_007_quarantine_pod, pb_004_cordon_node],
    "container-escape":       [pb_007_quarantine_pod, pb_004_cordon_node],
    "dns-exfiltration":       [pb_008_egress_quarantine],
    "rbac-privilege-escalation": [pb_005_revoke_rbac],
    "fraud-ml":               [pb_003_freeze_account, pb_006_kill_session_family],
}


async def dispatch(off: Offense, ctx: Context) -> list[ActionResult]:
    """Look up the rule_id and run every matching playbook."""
    plays = DISPATCH.get(off.rule_id, [])
    results: list[ActionResult] = []
    for p in plays:
        try:
            results.append(await p(off, ctx))
        except Exception as exc:  # noqa: BLE001
            results.append(ActionResult(playbook=p.__name__, success=False, error=str(exc)))
    return results
