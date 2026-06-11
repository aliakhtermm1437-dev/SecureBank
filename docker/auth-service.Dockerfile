# syntax=docker/dockerfile:1.7
# SecureBank Auth Service — hardened multi-stage build.
# Mapped controls: CIS Docker 4.1/4.5/4.6/4.9, ASVS V14.x, NIST 800-53 SC-7/SI-7.

# ---------- Stage 1: build wheels ----------
FROM python:3.11-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/shared /build/shared
COPY src/auth-service /build/svc
RUN pip wheel --wheel-dir /wheels /build/shared && \
    pip install --no-deps --prefix=/install --no-index --find-links=/wheels securebank-shared && \
    pip install --prefix=/install --no-cache-dir \
        fastapi 'uvicorn[standard]' pydantic pydantic-settings sqlalchemy asyncpg \
        redis argon2-cffi 'pyjwt[crypto]' cryptography hvac httpx \
        'opentelemetry-instrumentation-fastapi' prometheus-client python-json-logger \
        structlog pyotp 'qrcode[pil]' slowapi bleach email-validator tenacity

# ---------- Stage 2: runtime ----------
FROM gcr.io/distroless/python3-debian12:nonroot
LABEL org.opencontainers.image.title="securebank/auth-service"
LABEL org.opencontainers.image.description="OAuth2/OIDC + JWT auth service"
LABEL org.opencontainers.image.source="https://github.com/securebank/auth-service"

ENV PYTHONPATH=/install/lib/python3.11/site-packages:/app \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SB_SERVICE_NAME=auth-service SB_BIND_PORT=8001

COPY --from=builder /install /install
COPY src/auth-service /app
COPY src/shared/securebank_shared /install/lib/python3.11/site-packages/securebank_shared

USER nonroot
WORKDIR /app
EXPOSE 8001

# Healthcheck — CIS 4.6
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python","-c","import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8001/health',timeout=2).status==200 else sys.exit(1)"]

ENTRYPOINT ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001",
            "--no-server-header", "--proxy-headers", "--forwarded-allow-ips=*",
            "--log-config", "/dev/null"]
