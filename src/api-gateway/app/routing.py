"""Path-prefix → upstream routing table."""
from __future__ import annotations

from app.settings import settings

ROUTES: dict[str, str] = {
    "/v1/auth": settings.upstream_auth,
    "/v1/accounts": settings.upstream_account,
    "/v1/transactions": settings.upstream_tx,
    "/v1/notifications": settings.upstream_notification,
}

# Some auth subpaths must remain anonymous.
ANON_PATH_PREFIXES = (
    "/v1/auth/register",
    "/v1/auth/login",
    "/v1/auth/mfa/verify",
    "/v1/auth/token/refresh",
    "/v1/auth/.well-known/",
)


def resolve_upstream(path: str) -> str | None:
    for prefix, base in ROUTES.items():
        if path.startswith(prefix):
            return base
    return None


def requires_auth(path: str) -> bool:
    return not path.startswith(ANON_PATH_PREFIXES)
