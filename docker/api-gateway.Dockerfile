# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/shared /build/shared
COPY src/api-gateway /build/svc
RUN pip wheel --wheel-dir /wheels /build/shared && \
    pip install --no-deps --prefix=/install --no-index --find-links=/wheels securebank-shared && \
    pip install --prefix=/install --no-cache-dir \
        fastapi 'uvicorn[standard]' pydantic pydantic-settings httpx 'pyjwt[crypto]' \
        cryptography prometheus-client python-json-logger structlog slowapi tenacity

FROM gcr.io/distroless/python3-debian12:nonroot
ENV PYTHONPATH=/install/lib/python3.11/site-packages:/app \
    SB_SERVICE_NAME=api-gateway SB_BIND_PORT=8443
COPY --from=builder /install /install
COPY src/api-gateway /app
COPY src/shared/securebank_shared /install/lib/python3.11/site-packages/securebank_shared
USER nonroot
WORKDIR /app
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python","-c","import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8443/health',timeout=2).status==200 else sys.exit(1)"]
ENTRYPOINT ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8443","--no-server-header"]
