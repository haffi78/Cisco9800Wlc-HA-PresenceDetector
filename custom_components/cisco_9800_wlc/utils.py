"""Utility helpers for Cisco 9800 WLC integration."""
from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import quote


def _split_ipv6_zone(value: str) -> tuple[str, str | None]:
    if "%" in value:
        base, zone = value.split("%", 1)
        return base, zone
    return value, None


def _is_ipv6_literal(value: str) -> bool:
    base, _zone = _split_ipv6_zone(value)
    try:
        return ip_address(base).version == 6
    except ValueError:
        return False


def _encode_ipv6_zone(value: str) -> str:
    base, zone = _split_ipv6_zone(value)
    if not zone:
        return base
    return f"{base}%25{quote(zone, safe='')}"


def format_host_for_url(host: str) -> str:
    """Normalize a host for URL usage, adding IPv6 brackets when needed."""
    if not isinstance(host, str):
        return ""
    host = host.strip()
    if not host:
        return host
    if host.startswith("[") and "]" in host:
        return host
    if host.count(":") == 1:
        return host

    base = host
    port: str | None = None
    if host.count(":") >= 2:
        maybe_base, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit() and _is_ipv6_literal(maybe_base):
            base = maybe_base
            port = maybe_port

    if _is_ipv6_literal(base):
        formatted = f"[{_encode_ipv6_zone(base)}]"
        if port:
            return f"{formatted}:{port}"
        return formatted
    return host


def build_https_url(host: str, path: str | None = None) -> str:
    """Build an https URL from a host and optional path."""
    normalized = format_host_for_url(host)
    if not normalized:
        return ""
    if not path:
        return f"https://{normalized}"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"https://{normalized}{path}"
