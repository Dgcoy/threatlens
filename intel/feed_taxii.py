"""TAXII 2.x collection poller.

Feed config:
  source_url: discovery URL of the TAXII server
  parser_config: {collection_id: str, version: "2.0"|"2.1"}
  auth_json: {username, password} (Basic Auth; e.g. Anomali Limo guest/guest)
"""

from __future__ import annotations

from feed_stix import extract_stix_objects


def _load_client(version: str):
    if version == "2.1":
        from taxii2client.v21 import Collection, Server
    else:
        from taxii2client.v20 import Collection, Server
    return Server, Collection


def poll_taxii(feed: dict, *, timeout: int = 60) -> list[dict]:
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

    envelope = coll.get_objects()
    objects = envelope.get("objects", []) if isinstance(envelope, dict) else []
    return extract_stix_objects(objects)
