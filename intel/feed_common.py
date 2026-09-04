"""Shared helpers for feed pullers: download, IOC type inference."""

from __future__ import annotations

import ipaddress
import re

import requests

from shared.ioc_utils import url_hostname  # noqa: F401  (re-export)

DEFAULT_UA = "Watchman/0.1"
MAX_BYTES = 20 * 1024 * 1024  # 20 MB cap per feed payload


def download_text(url: str, *, user_agent: str | None = None,
                  timeout: int = 60) -> str:
    """GET a feed payload, capped at MAX_BYTES. Raises on HTTP error."""
    resp = requests.get(
        url,
        headers={"User-Agent": user_agent or DEFAULT_UA},
        timeout=timeout,
        stream=True,
    )
    resp.raise_for_status()
    chunks = []
    size = 0
    for chunk in resp.iter_content(chunk_size=65536):
        size += len(chunk)
        if size > MAX_BYTES:
            raise ValueError(f"feed payload exceeds {MAX_BYTES} bytes: {url}")
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9*_-]+(\.[a-zA-Z0-9*_-]+)+\.?$")
_QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def infer_type(value: str) -> str | None:
    """Classify a feed line/value as ip, cidr, domain, url — or None if junk."""
    v = value.strip().strip("\"'")
    if not v:
        return None
    if "://" in v:                      # URLs contain '/', check before CIDR
        return "url"
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            return None
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _QUAD_RE.match(v):               # looks like an IP but is invalid → junk
        return None
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


def clean_value(value: str) -> str:
    return value.strip().strip("\"'")
