"""SecureBank shared security & infrastructure utilities.

All public helpers live in submodules and are re-exported here for convenience.
"""
from securebank_shared.config import BaseServiceSettings
from securebank_shared.logging import configure_logging, get_logger, RedactingFilter
from securebank_shared.crypto import (
    aesgcm_encrypt,
    aesgcm_decrypt,
    hmac_sign,
    hmac_verify,
    constant_time_eq,
)
from securebank_shared.auth import (
    hash_password,
    verify_password,
    issue_jwt,
    verify_jwt,
    JWTClaims,
)
from securebank_shared.validation import (
    SafeEmail,
    SafePhoneNumber,
    AccountNumber,
    Amount,
    SafeMemo,
)
from securebank_shared.url_safety import validate_webhook_url, UnsafeUrlError
from securebank_shared.audit import AuditLogger
from securebank_shared.vault import VaultClient
from securebank_shared.middleware import install_security_middleware

__all__ = [
    "BaseServiceSettings",
    "configure_logging",
    "get_logger",
    "RedactingFilter",
    "aesgcm_encrypt",
    "aesgcm_decrypt",
    "hmac_sign",
    "hmac_verify",
    "constant_time_eq",
    "hash_password",
    "verify_password",
    "issue_jwt",
    "verify_jwt",
    "JWTClaims",
    "SafeEmail",
    "SafePhoneNumber",
    "AccountNumber",
    "Amount",
    "SafeMemo",
    "validate_webhook_url",
    "UnsafeUrlError",
    "AuditLogger",
    "VaultClient",
    "install_security_middleware",
]
