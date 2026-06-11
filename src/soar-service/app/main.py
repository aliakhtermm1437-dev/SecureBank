"""SOAR FastAPI app.

Endpoints
---------
POST /webhooks/qradar      QRadar offense → playbook dispatch
POST /webhooks/falco       Falco event   → playbook dispatch
POST /webhooks/ml          ML anomaly    → playbook dispatch
GET  /playbooks            List registered playbooks (admin only)
GET  /history              Recent playbook executions (admin only)
GET  /health, /ready, /metrics
"""
from __future__ import annotations

import hmac
import hashlib
import json
import logging
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Header, Request, status
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

from securebank_shared import configure_logging, get_logger, install_security_middleware
from .playbooks import Context, Offense, dispatch
from .settings import Settings

configure_logging()
log = get_logger(__name__)

PB_EXECUTED = Counter(
    "soar_playbook_executions_total",
    "Total SOAR playbook executions",
    ["playbook", "success"],
)
OFFENSES_IN = Counter(
    "soar_offenses_in_total",
    "Total offenses received",
    ["source", "rule_id"],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()  # type: ignore[call-arg]
    try:
        k8s_config.load_incluster_config()
    except Exception:
        try:
            k8s_config.load_kube_config(settings.kubeconfig_path)
        except Exception:
            log.warning("no kubeconfig available — playbooks that touch K8s will fail")
    app.state.settings = settings
    app.state.redis = redis.from_url(settings.redis_url, decode_responses=True)
    app.state.http = httpx.AsyncClient(verify=True, timeout=10.0)
    app.state.k8s_core = k8s_client.CoreV1Api()
    app.state.k8s_apps = k8s_client.AppsV1Api()
    app.state.k8s_net  = k8s_client.NetworkingV1Api()
    app.state.k8s_rbac = k8s_client.RbacAuthorizationV1Api()
    log.info("soar.startup", extra={"dry_run": settings.dry_run})
    try:
        yield
    finally:
        await app.state.http.aclose()
        await app.state.redis.aclose()


app = FastAPI(title="SecureBank SOAR", version="1.0.0", lifespan=lifespan)
install_security_middleware(app)


# ----------------------------------------------------------- helpers

def _verify_qradar_signature(secret: str, body: bytes, signature: str | None) -> None:
    if not signature or not signature.startswith("sha256="):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing signature")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.removeprefix("sha256="), expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad signature")


async def _ctx(request: Request) -> Context:
    s = request.app.state
    return Context(
        redis=s.redis,
        k8s_core=s.k8s_core, k8s_apps=s.k8s_apps,
        k8s_net=s.k8s_net,   k8s_rbac=s.k8s_rbac,
        http=s.http,
        auth_url=s.settings.auth_service_url,
        account_url=s.settings.account_service_url,
        dry_run=s.settings.dry_run,
    )


# ----------------------------------------------------------- webhooks

@app.post("/webhooks/qradar")
async def qradar_webhook(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
):
    body = await request.body()
    settings = request.app.state.settings
    _verify_qradar_signature(settings.qradar_webhook_secret, body, x_signature)
    payload = json.loads(body)

    off = Offense(
        offense_id=str(payload.get("offense_id") or payload.get("id") or "unknown"),
        source="qradar",
        rule_id=str(payload.get("rule") or payload.get("rule_id") or "unknown"),
        severity=str(payload.get("severity", "medium")).lower(),
        raw=payload,
        namespace=payload.get("namespace"),
        pod=payload.get("pod"),
        user_sub=payload.get("user_sub"),
        src_ip=payload.get("src_ip"),
        account_id=payload.get("account_id"),
    )
    return await _run(off, request)


@app.post("/webhooks/falco")
async def falco_webhook(payload: dict, request: Request):
    out = payload.get("output_fields", {})
    off = Offense(
        offense_id=str(payload.get("uuid") or payload.get("time") or ""),
        source="falco",
        rule_id=str(payload.get("rule", "unknown")).replace(" ", "-").lower(),
        severity=str(payload.get("priority", "warning")).lower(),
        raw=payload,
        namespace=out.get("k8s.ns.name"),
        pod=out.get("k8s.pod.name"),
    )
    return await _run(off, request)


@app.post("/webhooks/ml")
async def ml_webhook(payload: dict, request: Request):
    off = Offense(
        offense_id=str(payload.get("event_id")),
        source="ml",
        rule_id="fraud-ml",
        severity="high",
        raw=payload,
        user_sub=payload.get("actor_sub"),
        account_id=payload.get("src_account_id"),
    )
    return await _run(off, request)


async def _run(off: Offense, request: Request):
    OFFENSES_IN.labels(off.source, off.rule_id).inc()
    redis_client = request.app.state.redis
    if await redis_client.set(f"soar:dedupe:{off.dedupe_key}",
                              off.offense_id, nx=True, ex=300) is None:
        log.info("soar.duplicate", extra={"offense_id": off.offense_id})
        return {"status": "deduplicated"}

    ctx = await _ctx(request)
    results = await dispatch(off, ctx)
    for r in results:
        PB_EXECUTED.labels(r.playbook, str(r.success).lower()).inc()
    audit = [{"playbook": r.playbook, "success": r.success,
              "actions": r.actions, "error": r.error} for r in results]
    log.info("soar.dispatch", extra={"offense_id": off.offense_id,
                                     "rule_id": off.rule_id, "results": audit})
    return {"offense_id": off.offense_id, "playbooks": audit}


# ----------------------------------------------------------- meta

@app.get("/health")
async def health(): return {"status": "ok"}


@app.get("/ready")
async def ready(): return {"status": "ready"}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
