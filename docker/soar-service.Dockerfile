# SecureBank SOAR — hardened multi-stage build
# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && rm -rf /var/lib/apt/lists/*
COPY src/shared/        ./shared/
COPY src/soar-service/  ./soar-service/
RUN pip install --prefix=/install ./shared
RUN pip install --prefix=/install ./soar-service

FROM gcr.io/distroless/python3-debian12:nonroot
COPY --from=build /install /usr/local
WORKDIR /app
COPY src/soar-service/app/ ./app/
USER nonroot
EXPOSE 8006
HEALTHCHECK CMD ["/usr/local/bin/python","-c","import urllib.request,sys;urllib.request.urlopen('http://127.0.0.1:8006/health',timeout=2)"]
ENTRYPOINT ["/usr/local/bin/python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8006","--no-server-header"]
