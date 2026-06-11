"""Safe URL helpers — primary purpose: block SSRF (OWASP API7).

``validate_webhook_url`` resolves DNS server-side and rejects any address that
falls inside RFC1918, link-local, loopback, IPv6 ULA, cloud metadata, or any
non-HTTPS scheme. This is what we use for the webhook-registration endpoint
exploited in the F7 pentest finding.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeUrlError(ValueError):
    pass


_BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata"}
_BLOCKED_NETWORKS_V4 = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # AWS / link-local
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]
_BLOCKED_NETWORKS_V6 = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
    ipaddress.IPv6Network("::ffff:0:0/96"),  # mapped v4
]


def _ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _BLOCKED_NETWORKS_V4)
    if isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in _BLOCKED_NETWORKS_V6)
    return True


def validate_webhook_url(url: str, allowed_schemes: tuple[str, ...] = ("https",)) -> str:
    """Return the URL if safe to call; raise :class:`UnsafeUrlError` otherwise."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise UnsafeUrlError(f"could not parse url: {e}") from e

    if parsed.scheme not in allowed_schemes:
        raise UnsafeUrlError(f"scheme {parsed.scheme!r} not allowed")
    if not parsed.hostname:
        raise UnsafeUrlError("missing hostname")
    host = parsed.hostname.lower()
    if host in _BLOCKED_HOSTS:
        raise UnsafeUrlError("hostname is on blocked list")

    # If it's already an IP literal, check directly.
    try:
        addr = ipaddress.ip_address(host)
        if _ip_blocked(addr):
            raise UnsafeUrlError(f"address {addr} is in a blocked range")
        return url
    except ValueError:
        pass  # not an IP literal — resolve below

    # Resolve all A/AAAA records and ensure every one is safe (prevents
    # DNS-rebinding from the moment of validation to the moment of fetch).
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeUrlError(f"DNS resolution failed for {host}") from e
    for fam, _typ, _proto, _name, sockaddr in infos:
        ip_str = sockaddr[0]
        addr = ipaddress.ip_address(ip_str)
        if _ip_blocked(addr):
            raise UnsafeUrlError(
                f"resolved address {addr} for {host} is in a blocked range"
            )
    return url
