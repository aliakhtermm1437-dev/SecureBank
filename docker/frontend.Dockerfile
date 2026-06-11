# Static-file server for the demo SPA.
FROM nginx:1.27-alpine
RUN apk add --no-cache curl tini && \
    adduser -D -u 10001 web && \
    sed -i 's/user  nginx;/user  web;/' /etc/nginx/nginx.conf
COPY src/frontend/ /usr/share/nginx/html/
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
USER 10001
HEALTHCHECK CMD curl -fsS http://127.0.0.1:8080/ -o /dev/null || exit 1
EXPOSE 8080
