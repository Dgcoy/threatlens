"""STIX 2.x bundle parsing → ThreatLens IOC records.

Handles both indicator SDOs (pattern-based) and bare observable SDOs
(ipv4-addr / ipv6-addr / domain-name / url).
"""

from __future__ import annotations

import json
import re

PATTERN_EQ_RE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url)(?::value)?\s*=\s*'([^']+)'"
)
PATTERN_IN_RE = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url)(?::value)?\s+IN\s*\(([^)]*)\)"
)

KIND_MAP = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
}


def _split_in_values(inside: str) -> list[str]:
    return [v.strip().strip("'\"") for v in inside.split(",") if v.strip()]


def extract_pattern_values(pattern: str) -> list[tuple[str, str]]:
    """Return [(kind, value), ...] from a STIX pattern string."""
    found = []
    for m in PATTERN_EQ_RE.finditer(pattern):
        found.append((m.group(1), m.group(2)))
    for m in PATTERN_IN_RE.finditer(pattern):
        for v in _split_in_values(m.group(2)):
            found.append((m.group(1), v))
    return found


def _ref_url(obj: dict) -> str | None:
    refs = obj.get("external_references") or []
    for r in refs:
        if r.get("url"):
            return r["url"]
    return None


def _obj_to_ioc(obj: dict) -> dict | None:
    otype = obj.get("type")
    if otype == "indicator":
        pattern = obj.get("pattern")
        if not pattern:
            return None
        # an indicator may contain multiple observable kinds — emit the first
        # (most specific) kind; keep others as tags
        pairs = extract_pattern_values(pattern)
        if not pairs:
            return None
        kind, value = pairs[0]
        ioc_type = KIND_MAP.get(kind)
        if ioc_type is None:
            return None
        extra = [v for k, v in pairs[1:] if k in KIND_MAP]
        tags = list(obj.get("labels") or [])
        if extra:
            tags.extend(extra)
        return {
            "type": ioc_type,
            "value": value,
            "description": obj.get("description"),
            "tags": tags or None,
            "severity": (obj.get("x_threatlens_severity") or obj.get("confidence")),
            "reference": _ref_url(obj),
            "first_seen": obj.get("created"),
            "last_seen": obj.get("modified"),
        }
    if otype in KIND_MAP:
        return {
            "type": KIND_MAP[otype],
            "value": obj.get("value"),
            "description": obj.get("name") or obj.get("description"),
            "tags": obj.get("labels") or None,
            "severity": None,
            "reference": _ref_url(obj),
            "first_seen": obj.get("created"),
            "last_seen": obj.get("modified"),
        }
    return None


def extract_stix_objects(objects: list[dict]) -> list[dict]:
    """Convert STIX objects (indicators + observables) to IOC records."""
    iocs = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        ioc = _obj_to_ioc(obj)
        if ioc and ioc["value"]:
            iocs.append(ioc)
    return iocs


def parse_bundle(text: str) -> list[dict]:
    """Parse a STIX 2.x bundle (JSON) into IOC records."""
    data = json.loads(text)
    if isinstance(data, dict):
        objects = data.get("objects", [])
        if not objects and data.get("type") == "indicator":
            objects = [data]
    elif isinstance(data, list):
        objects = data
    else:
        objects = []
    return extract_stix_objects(objects)
