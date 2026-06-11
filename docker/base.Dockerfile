# Shared Python base — distroless runtime, non-root, multi-stage.
# CIS Docker 4.x compliant; image is digest-pinned by CI.

FROM python:3.11-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/shared/pyproject.toml /build/shared/pyproject.toml
COPY src/shared/securebank_shared /build/shared/securebank_shared
RUN pip install --prefix=/install /build/shared

FROM gcr.io/distroless/python3-debian12:nonroot AS runtime
ENV PYTHONPATH=/install/lib/python3.11/site-packages
COPY --from=builder /install /install
USER nonroot
