"""SecureBank AI Security Agent — FastAPI app."""
from __future__ import annotations

from contextlib import asynccontextmanager

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field

from securebank_shared import configure_logging, get_logger, install_security_middleware

from .adversarial import load_model, robustness_report
from .code_review import scan_text
from .reasoner import build_reasoner, Explanation
from .settings import Settings

configure_logging()
log = get_logger(__name__)

EXPLAINS = Counter("ai_agent_explanations_total", "Explanations served",
                   ["backend", "rule_id"])
REVIEWS  = Counter("ai_agent_reviews_total",      "Code reviews served")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = Settings()  # type: ignore[call-arg]
    app.state.settings = s
    app.state.reasoner = build_reasoner(s.llm_provider, s.llm_api_key, s.llm_model)
    app.state.fraud_model = load_model(s.fraud_model_path)
    log.info("ai-agent.startup", extra={"backend": app.state.reasoner.backend})
    yield


app = FastAPI(title="SecureBank AI Security Agent", version="1.0.0", lifespan=lifespan)
install_security_middleware(app)


# --------------------------------------------------------- /explain

class ExplainRequest(BaseModel):
    rule_id: str = Field(..., min_length=2, max_length=128)
    context: dict = Field(default_factory=dict)


@app.post("/explain", response_model=dict)
async def explain(req: ExplainRequest) -> dict:
    r: Explanation = app.state.reasoner.explain(req.rule_id, req.context)
    EXPLAINS.labels(r.backend, req.rule_id).inc()
    return r.as_dict()


# --------------------------------------------------------- /triage

class TriageRequest(BaseModel):
    rule_id: str
    severity_hint: str | None = None
    context: dict = Field(default_factory=dict)


@app.post("/triage")
async def triage(req: TriageRequest) -> dict:
    r = app.state.reasoner.explain(req.rule_id, req.context)
    # Bump severity if the caller hinted at higher
    order = ["info", "low", "medium", "high", "critical"]
    if req.severity_hint and order.index(req.severity_hint.lower()) > order.index(r.severity):
        r.severity = req.severity_hint.lower()
    return {**r.as_dict(), "triage_score": order.index(r.severity)}


# --------------------------------------------------------- /review

class ReviewRequest(BaseModel):
    filename: str
    content:  str = Field(..., max_length=200_000)


@app.post("/review")
async def review(req: ReviewRequest) -> dict:
    findings = scan_text(req.content, req.filename)
    REVIEWS.inc()
    return {
        "filename": req.filename,
        "finding_count": len(findings),
        "findings": [f.as_dict() for f in findings],
    }


# --------------------------------------------------------- /adversarial

class AdversarialRequest(BaseModel):
    base_features:      list[float]
    historical_amounts: list[float]
    recent_amounts:     list[float]


@app.post("/adversarial/score")
async def adversarial_score(req: AdversarialRequest) -> dict:
    if not req.base_features:
        raise HTTPException(400, "base_features must not be empty")
    rep = robustness_report(
        app.state.fraud_model,
        np.asarray(req.base_features,      dtype=float),
        np.asarray(req.historical_amounts, dtype=float),
        np.asarray(req.recent_amounts,     dtype=float),
    )
    return rep.as_dict()


# --------------------------------------------------------- meta

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict:
    return {"status": "ready", "backend": app.state.reasoner.backend}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
