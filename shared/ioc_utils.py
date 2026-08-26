"""Small shared helpers used by both collector and intel services."""

from __future__ import annotations

import re

_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", re.I)


def url_hostname(url: str) -> str | None:
    """Best-effort hostname from a URL (for domain-side IOC matching)."""
    m = _URL_SCHEME_RE.match(url.strip())
    return m.group(1) if m else None
