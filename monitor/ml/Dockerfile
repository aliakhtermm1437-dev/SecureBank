# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN pip install --prefix=/install --no-cache-dir \
        fastapi 'uvicorn[standard]' joblib numpy pandas scikit-learn

FROM gcr.io/distroless/python3-debian12:nonroot
ENV PYTHONPATH=/install/lib/python3.11/site-packages
COPY --from=builder /install /install
COPY serve_log_anomaly.py /app/serve.py
USER nonroot
WORKDIR /app
EXPOSE 9100
ENTRYPOINT ["python","-m","uvicorn","serve:app","--host","0.0.0.0","--port","9100","--no-server-header"]
