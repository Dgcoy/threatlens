"""TAXII 2.x collection poller.

Feed config:
  source_url: discovery URL of the TAXII server
  parser_config: {collection_id: str, version: "2.0"|"2.1"}
  auth_json: {username, password} (Basic Auth; e.g. Anomali Limo guest/guest)
"""

from __future__ import annotations

import time

import requests

from feed_stix import extract_stix_objects

# OTX and several other TAXII servers sit behind WAFs that 404 non-browser
# User-Agents (misleading "Collection not found"). taxii2client forces its own
# UA on every request *unless* the session already carries one — so we inject
# a browser-like UA at the session layer.
TAXII_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


def _install_browser_ua() -> None:
    if getattr(requests.Session, "_watchman_ua", False):
        return
    orig = requests.Session

    class _BrowserUASession(orig):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.headers["User-Agent"] = TAXII_USER_AGENT

    _BrowserUASession._watchman_ua = True  # type: ignore[attr-defined]
    requests.Session = _BrowserUASession


def _load_client(version: str):
    if version == "2.1":
        from taxii2client.v21 import Collection, Server
    else:
        from taxii2client.v20 import Collection, Server
    return Server, Collection


def poll_taxii(feed: dict, *, timeout: int = 60) -> list[dict]:
    _install_browser_ua()
    cfg = feed.get("parser_config") or {}
    auth = feed.get("auth_json") or {}
    version = cfg.get("version", "2.0")
    Server, _Collection = _load_client(version)

    server = Server(
        feed["source_url"],
        user=auth.get("username"),
        password=auth.get("password"),
    )

    collection_id = cfg.get("collection_id")
    collections = [
        c
        for ar in server.api_roots
        for c in ar.collections
    ]
    if collection_id:
        matches = [c for c in collections if c.id == collection_id]
        if not matches:
            raise ValueError(f"collection {collection_id} not found on server")
        coll = matches[0]
    elif collections:
        coll = collections[0]
    else:
        raise ValueError("TAXII server exposes no collections")

    envelope = _get_objects_with_retry(coll, timeout=timeout)
    objects = envelope.get("objects", []) if isinstance(envelope, dict) else []
    return extract_stix_objects(objects)


def _get_objects_with_retry(coll, *, timeout: int = 60, attempts: int = 3):
    """Fetch objects with retries — OTX-style WAFs intermittently 404/5xx
    even with a browser UA (rate limiting), so transient failures retry."""
    last = None
    for i in range(attempts):
        try:
            return coll.get_objects()
        except Exception as exc:  # taxii2client raises generic exceptions
            last = exc
            time.sleep(1.5 * (i + 1))
    raise last  # type: ignore[misc]
