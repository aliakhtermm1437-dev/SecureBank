import pytest

from securebank_shared.url_safety import UnsafeUrlError, validate_webhook_url


@pytest.mark.parametrize("url", [
    "http://example.com/",                      # http
    "https://127.0.0.1/",                       # loopback v4 literal
    "https://[::1]/",                           # loopback v6
    "https://10.0.0.1/",                        # rfc1918
    "https://169.254.169.254/latest/meta-data", # AWS metadata
    "https://192.168.1.10/",
    "https://localhost/",
    "ftp://example.com",
])
def test_unsafe(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_webhook_url(url)


def test_safe() -> None:
    # public domain — relies on DNS, but every public IP we'd resolve is not blocked
    assert validate_webhook_url("https://example.com/")
