"""TAXII discovery helper for the dashboard feed form.

Implements the TAXII 2.x discovery flow with plain requests (no heavy
dependencies in the api image):
  1. GET discovery URL (Accept: application/taxii+json;version=2.1,
     fall back to 2.0) → api_roots
  2. GET each api root's /collections/ → collection list
"""

from __future__ import annotations

import requests

ACCEPT_21 = "application/taxii+json;version=2.1"
ACCEPT_20 = "application/taxii+json;version=2.0"
DEFAULT_TIMEOUT = 20


def _get_json(url: str, accept: str, auth, timeout: int) -> dict:
    resp = requests.get(url, headers={"Accept": accept}, auth=auth, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def discover_taxii(discovery_url: str, auth=None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Resolve a TAXII discovery URL into its collections.

    Returns {"version", "api_roots", "collections": [{id, title, description,
    api_root, can_read}]}. Raises ValueError if the server accepts neither
    TAXII 2.1 nor 2.0.
    """
    last_error = None
    for version, accept in (("2.1", ACCEPT_21), ("2.0", ACCEPT_20)):
        try:
            disc = _get_json(discovery_url, accept, auth, timeout)
        except requests.HTTPError as exc:
            # 406/415 = wrong version advertised; 404 = wrong discovery path
            if exc.response is not None and exc.response.status_code in (406, 415, 404):
                last_error = exc
                continue
            raise ValueError(f"discovery failed: HTTP {exc.response.status_code if exc.response else exc}")
        except requests.RequestException as exc:
            raise ValueError(f"discovery failed: {exc}")

        api_roots = list(disc.get("api_roots") or [])
        if not api_roots and disc.get("default"):
            api_roots = [disc["default"]]

        collections = []
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
            except (requests.RequestException, ValueError):
                continue   # a root may be unreachable/require auth — skip it

        return {"version": version, "api_roots": api_roots, "collections": collections}

    raise ValueError("server did not accept TAXII 2.1 or 2.0 "
                     f"({last_error})")
