"""TAXII discovery helper for the dashboard feed form.

Implements the TAXII 2.x discovery flow with plain requests (no heavy
dependencies in the api image):
  1. GET discovery URL (Accept: application/taxii+json;version=2.1,
     fall back to 2.0) → api_roots
  2. GET each api root's /collections/ → collection list

Transient failures (timeouts, 5xx, 408/429) are retried with backoff —
real TAXII servers (e.g. AlienVault OTX) are often slow/flaky.
"""

from __future__ import annotations

import time

import requests
from requests.exceptions import HTTPError, ReadTimeout, RequestException

ACCEPT_21 = "application/taxii+json;version=2.1"
ACCEPT_20 = "application/taxii+json;version=2.0"
DEFAULT_TIMEOUT = 30
RETRIES = 3


def _is_transient(exc: Exception) -> bool:
    """Timeout/5xx/429/408 → retry; 4xx (other) → permanent."""
    if isinstance(exc, ReadTimeout) or isinstance(exc, requests.ConnectionError):
        return True
    if isinstance(exc, HTTPError) and exc.response is not None:
        return exc.response.status_code in (408, 429) or exc.response.status_code >= 500
    return False


def _get_json(url: str, accept: str, auth, timeout: int) -> dict:
    last = None
    for attempt in range(RETRIES):
        try:
            resp = requests.get(url, headers={"Accept": accept}, auth=auth,
                                timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except RequestException as exc:
            if not _is_transient(exc):
                raise
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise last  # type: ignore[misc]


def discover_taxii(discovery_url: str, auth=None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Resolve a TAXII discovery URL into its collections.

    Returns {"version", "api_roots", "collections": [{id, title, description,
    api_root, can_read}], "errors": [...]}. Raises ValueError if the server
    accepts neither TAXII 2.1 nor 2.0, or if no collections could be reached.
    """
    # TAXII 1.x discovery paths (/taxii/discovery) are a common trap — the
    # server often answers them with a confusing 500 instead of a 404/406.
    path = discovery_url.split("?", 1)[0].rstrip("/")
    if path.endswith("/discovery") or path.endswith("/taxii/discovery"):
        raise ValueError(
            "that looks like a TAXII 1.x discovery URL — ThreatLens supports "
            "TAXII 2.0/2.1. Use the server's TAXII 2.x discovery URL "
            "(AlienVault OTX: https://otx.alienvault.com/taxii/)")
    last_error = None
    for version, accept in (("2.1", ACCEPT_21), ("2.0", ACCEPT_20)):
        try:
            disc = _get_json(discovery_url, accept, auth, timeout)
        except HTTPError as exc:
            # 406/415 = wrong version advertised; 404 = wrong discovery path
            if exc.response is not None and exc.response.status_code in (406, 415, 404):
                last_error = exc
                continue
            raise ValueError(f"discovery failed: HTTP {exc.response.status_code if exc.response else exc}")
        except RequestException as exc:
            raise ValueError(f"discovery failed: {exc}")

        api_roots = list(disc.get("api_roots") or [])
        if not api_roots and disc.get("default"):
            api_roots = [disc["default"]]

        collections, errors = [], []
        for root_url in api_roots:
            try:
                root = _get_json(root_url, accept, auth, timeout)
                coll_url = root_url.rstrip("/") + "/collections/"
                data = _get_json(coll_url, accept, auth, timeout)
                for c in data.get("collections", []):
                    collections.append({
                        "id": c.get("id"),
                        "title": c.get("title"),
                        "description": c.get("description"),
                        "api_root": root_url,
                        "can_read": c.get("can_read"),
                    })
            except RequestException as exc:
                errors.append({"api_root": root_url,
                               "error": str(exc)[:250]})

        if not collections and errors:
            raise ValueError(
                f"could not reach collections for any API root: {errors[0]['error']}")

        return {"version": version, "api_roots": api_roots,
                "collections": collections, "errors": errors}

    raise ValueError("server did not accept TAXII 2.1 or 2.0 "
                     f"({last_error})")
