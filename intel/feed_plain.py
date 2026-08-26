"""Plain-text and CSV feed pullers.

plain: one indicator per line (IP/CIDR/domain/URL), auto-detected;
       '#' / ';' comment lines and trailing comments are skipped.
csv:   configurable column mapping (1-based columns):
       {has_header, delimiter, value_column, description_column,
        tags_column, reference_column}
"""

from __future__ import annotations

import csv
import io

from feed_common import clean_value, download_text, infer_type
from shared.ioc_utils import url_hostname


def parse_plain(text: str, cfg: dict | None = None) -> list[dict]:
    cfg = cfg or {}
    iocs = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        # drop trailing comment ("1.2.3.0/24 ; SBL12345")
        token = line.split(";", 1)[0].strip()
        if not token:
            continue
        first = token.split()[0] if token.split() else token
        kind = infer_type(first)
        if kind is None:
            continue
        iocs.append({
            "type": kind,
            "value": clean_value(first),
            "description": None,
            "tags": None,
            "severity": None,
            "reference": None,
        })
    return iocs


def _col(cols: list[str], idx, default=None):
    if idx is None:
        return default
    i = int(idx) - 1  # config columns are 1-based
    if 0 <= i < len(cols):
        v = cols[i].strip().strip("\"'")
        if v and v.lower() not in ("none", "null"):
            return v
    return default


def parse_csv(text: str, cfg: dict | None = None) -> list[dict]:
    cfg = cfg or {}
    delimiter = cfg.get("delimiter", ",")
    has_header = bool(cfg.get("has_header"))
    value_col = cfg.get("value_column", 1)
    desc_col = cfg.get("description_column")
    tags_col = cfg.get("tags_column")
    ref_col = cfg.get("reference_column")

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = list(reader)
    # abuse.ch feeds lead with several '#' comment rows before the header —
    # drop comment rows (first column starts with # or ;)
    rows = [r for r in rows
            if not (r and r[0].lstrip().startswith(("#", ";")))]
    if has_header:
        rows = rows[1:]

    iocs = []
    for cols in rows:
        if not cols or not any(c.strip() for c in cols):
            continue
        raw_value = _col(cols, value_col)
        if not raw_value:
            continue
        kind = infer_type(raw_value)
        if kind is None:
            continue
        tags = _col(cols, tags_col)
        iocs.append({
            "type": kind,
            "value": clean_value(raw_value),
            "description": _col(cols, desc_col),
            "tags": [t.strip() for t in tags.split(",") if t.strip()] if tags else None,
            "severity": None,
            "reference": _col(cols, ref_col) or None,
        })
    return iocs


def pull_plain(feed: dict, *, user_agent: str | None = None,
               timeout: int = 60) -> list[dict]:
    cfg = feed.get("parser_config") or {}
    if feed["type"] == "csv":
        text = download_text(feed["source_url"], user_agent=user_agent, timeout=timeout)
        return parse_csv(text, cfg)
    text = download_text(feed["source_url"], user_agent=user_agent, timeout=timeout)
    return parse_plain(text, cfg)
