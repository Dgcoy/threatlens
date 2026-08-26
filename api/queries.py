"""Query layer for the ThreatLens dashboard API."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from psycopg2.errors import UniqueViolation

from shared.schema import conn_from_env  # noqa: F401 (re-export)

FEED_TYPES = ("plain", "csv", "stix", "taxii")

# dashboard "bucket" taxonomy for live ingestion view (Palo-Alto-style)
BUCKET_ORDER = [
    "Firewall · DROP", "Firewall · ACCEPT", "Firewall · Rule", "IPS / DPIA",
    "DNS", "DHCP", "WLAN", "WAN", "System", "Kernel", "Other",
]


def bucket_of(ev: dict) -> str:
    """Categorize a normalized event into an ingestion bucket."""
    tag = (ev.get("tag") or "").lower()
    action = (ev.get("action") or "").upper()
    if tag == "kernel" or (not tag and action):
        if "DPIA" in action or "IPS" in action:
            return "IPS / DPIA"
        if "DROP" in action or "REJECT" in action:
            return "Firewall · DROP"
        if "ACCEPT" in action or "ALLOW" in action:
            return "Firewall · ACCEPT"
        if action:
            return "Firewall · Rule"
        return "Kernel"
    if tag == "dnsmasq-dhcp":
        return "DHCP"
    if tag == "dnsmasq":
        return "DNS"
    if tag == "hostapd":
        return "WLAN"
    if tag == "pppd":
        return "WAN"
    if tag in ("ubios", "unifi", "network", "syslog"):
        return "System"
    if tag == "kernel":
        return "Kernel"
    return "Other"

STATS_SQL = """
SELECT
  (SELECT count(*) FROM events WHERE ts >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS events_today,
  (SELECT count(*) FROM events) AS events_total,
  (SELECT count(*) FROM detections WHERE created_at >= now() - interval '24 hours') AS detections_24h,
  (SELECT count(*) FROM detections) AS detections_total,
  (SELECT count(*) FROM feeds WHERE enabled AND deleted_at IS NULL) AS active_feeds,
  (SELECT count(*) FROM feeds WHERE deleted_at IS NULL) AS feeds_total,
  (SELECT count(*) FROM iocs WHERE active) AS iocs_active,
  (SELECT count(*) FROM iocs) AS iocs_total
"""


def _rows(conn, sql, params=()):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def _row(conn, sql, params=()):
    rows = _rows(conn, sql, params)
    return rows[0] if rows else None


class Repo:
    def __init__(self, conn):
        self._conn = conn

    # ---- stats ----
    def stats(self) -> dict:
        return _row(self._conn, STATS_SQL)

    # ---- events ----
    def events(self, q: str | None = None, since: str | None = None,
               limit: int = 50, offset: int = 0,
               flows_only: bool = False) -> list[dict]:
        where, params = [], []
        if flows_only:
            # actual traffic only — kernel/system chatter has no SRC/DST
            where.append("(src_ip IS NOT NULL OR dst_ip IS NOT NULL)")
        if q:
            where.append(
                "(raw ILIKE %s OR src_ip::text ILIKE %s OR dst_ip::text ILIKE %s "
                "OR hostname ILIKE %s)")
            like = f"%{q}%"
            params += [like, like, like, like]
        if since:
            where.append("ts >= %s")
            params.append(since)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"""
            SELECT e.*, d.det_count
            FROM events e
            LEFT JOIN (SELECT event_id, count(*) AS det_count FROM detections
                       GROUP BY event_id) d ON d.event_id = e.id
            {clause}
            ORDER BY e.id DESC
            LIMIT %s OFFSET %s
        """
        return _rows(self._conn, sql, params + [limit, offset])

    def event(self, event_id: int) -> dict | None:
        row = _row(self._conn, "SELECT * FROM events WHERE id = %s", (event_id,))
        if row:
            row["detections"] = _rows(
                self._conn,
                """SELECT d.* FROM detections d
                   WHERE d.event_id = %s ORDER BY d.id""",
                (event_id,),
            )
        return row

    # ---- detections ----
    def detections(self, feed_id: int | None = None, q: str | None = None,
                   since: str | None = None, limit: int = 50,
                   offset: int = 0) -> list[dict]:
        where, params = [], []
        if feed_id:
            where.append("d.feed_id = %s")
            params.append(feed_id)
        if q:
            where.append("(d.matched_value ILIKE %s OR d.feed_name ILIKE %s)")
            like = f"%{q}%"
            params += [like, like]
        if since:
            where.append("d.created_at >= %s")
            params.append(since)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        sql = f"""
            SELECT d.id, d.created_at, d.match_type, d.matched_value,
                   d.feed_name, d.feed_id,
                   e.id AS event_id, e.ts AS event_ts, e.action AS event_action,
                   e.src_ip, e.dst_ip, e.hostname, e.tag AS event_tag,
                   e.src_port, e.dst_port, e.proto,
                   ioc.description AS ioc_description,
                   ioc.tags AS ioc_tags,
                   ioc.severity AS ioc_severity,
                   ioc.reference AS ioc_reference,
                   ioc.first_seen AS ioc_first_seen,
                   ioc.last_seen AS ioc_last_seen,
                   ioc.value AS ioc_value
            FROM detections d
            JOIN events e ON e.id = d.event_id
            LEFT JOIN iocs ioc ON ioc.id = d.ioc_id
            {clause}
            ORDER BY d.id DESC
            LIMIT %s OFFSET %s
        """
        return _rows(self._conn, sql, params + [limit, offset])

    def detection(self, det_id: int) -> dict | None:
        row = _row(self._conn, """
            SELECT d.*, e.raw AS event_raw, e.ts AS event_ts, e.host AS event_host,
                   e.action AS event_action, e.src_ip, e.dst_ip, e.hostname,
                   e.src_port, e.dst_port, e.proto, e.tag AS event_tag,
                   ioc.description AS ioc_description, ioc.tags AS ioc_tags,
                   ioc.severity AS ioc_severity, ioc.reference AS ioc_reference,
                   ioc.first_seen AS ioc_first_seen, ioc.last_seen AS ioc_last_seen,
                   ioc.value AS ioc_value, ioc.type AS ioc_type
            FROM detections d
            LEFT JOIN events e ON e.id = d.event_id
            LEFT JOIN iocs ioc ON ioc.id = d.ioc_id
            WHERE d.id = %s
        """, (det_id,))
        return row

    # ---- feeds ----
    def feeds(self) -> list[dict]:
        return _rows(self._conn, """
            SELECT id, name, type, source_url, auth_json, parser_config,
                   enabled, auto_pull_minutes, last_pull, last_status, last_error,
                   deleted_at, created_at,
                   (SELECT count(*) FROM iocs i WHERE i.feed_id = feeds.id AND i.active) AS ioc_count
            FROM feeds WHERE deleted_at IS NULL ORDER BY id
        """)

    def feed(self, feed_id: int) -> dict | None:
        return _row(self._conn, "SELECT * FROM feeds WHERE id = %s", (feed_id,))

    def create_feed(self, data: dict) -> dict:
        name = (data.get("name") or "").strip()
        ftype = data.get("type")
        url = (data.get("source_url") or "").strip()
        if not name:
            raise ValueError("name is required")
        if ftype not in FEED_TYPES:
            raise ValueError(f"type must be one of {FEED_TYPES}")
        if not url:
            raise ValueError("source_url is required")
        parser_config = data.get("parser_config") or {}
        auth_json = data.get("auth_json") or {}
        minutes = int(data.get("auto_pull_minutes") or 1440)
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO feeds (name, type, source_url, auth_json, parser_config, auto_pull_minutes)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                    (name, ftype, url,
                     psycopg2.extras.Json(auth_json),
                     psycopg2.extras.Json(parser_config), minutes),
                )
                feed_id = cur.fetchone()[0]
        except UniqueViolation:
            raise ValueError(f"a feed named {name!r} already exists")
        return self.feed(feed_id)

    def update_feed(self, feed_id: int, data: dict) -> dict | None:
        existing = self.feed(feed_id)
        if not existing or existing.get("deleted_at"):
            return None
        fields = []
        params = []
        for key in ("name", "type", "source_url", "auto_pull_minutes"):
            if key in data:
                fields.append(f"{key} = %s")
                params.append(data[key])
        for key in ("parser_config", "auth_json"):
            if key in data:
                fields.append(f"{key} = %s")
                params.append(psycopg2.extras.Json(data[key] or {}))
        if "enabled" in data:
            fields.append("enabled = %s")
            params.append(bool(data["enabled"]))
        if not fields:
            return self.feed(feed_id)
        params.append(feed_id)
        with self._conn.cursor() as cur:
            cur.execute(
                f"UPDATE feeds SET {', '.join(fields)} WHERE id = %s", params)
        self._conn.commit()
        return self.feed(feed_id)

    def delete_feed(self, feed_id: int) -> bool:
        """Soft delete + deactivate IOCs; detections keep feed_name snapshot."""
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE feeds SET deleted_at = now(), enabled = false WHERE id = %s",
                (feed_id,))
            cur.execute("UPDATE iocs SET active = false WHERE feed_id = %s",
                        (feed_id,))
        self._conn.commit()
        return True

    def request_pull(self, feed_id: int) -> bool:
        feed = self.feed(feed_id)
        if not feed or feed.get("deleted_at"):
            return False
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO feed_pull_requests (feed_id) VALUES (%s) RETURNING id",
                (feed_id,))
            req_id = cur.fetchone()[0]
        self._conn.commit()
        return bool(req_id)

    # ---- iocs ----
    def iocs(self, feed_id: int | None = None, ioc_type: str | None = None,
             q: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        where, params = ["i.active", "f.deleted_at IS NULL"], []
        if feed_id:
            where.append("i.feed_id = %s")
            params.append(feed_id)
        if ioc_type:
            where.append("i.type = %s")
            params.append(ioc_type)
        if q:
            where.append("(i.value ILIKE %s OR i.description ILIKE %s)")
            like = f"%{q}%"
            params += [like, like]
        sql = f"""
            SELECT i.id, i.type, i.value, i.description, i.tags, i.severity,
                   i.reference, i.first_seen, i.last_seen, i.active, i.created_at,
                   f.name AS feed_name
            FROM iocs i JOIN feeds f ON f.id = i.feed_id
            WHERE {' AND '.join(where)}
            ORDER BY i.id DESC LIMIT %s OFFSET %s
        """
        return _rows(self._conn, sql, params + [limit, offset])

    def ioc(self, ioc_id: int) -> dict | None:
        return _row(self._conn, """
            SELECT i.*, f.name AS feed_name
            FROM iocs i JOIN feeds f ON f.id = i.feed_id
            WHERE i.id = %s
        """, (ioc_id,))

    def feed_logs(self, feed_id: int, limit: int = 50) -> list[dict]:
        return _rows(self._conn, """
            SELECT id, feed_id, ts, level, message
            FROM feed_logs WHERE feed_id = %s
            ORDER BY ts DESC, id DESC LIMIT %s
        """, (feed_id, limit))

    # ---- live ingestion stream (WebSocket) ----
    def max_event_id(self) -> int:
        r = _row(self._conn, "SELECT COALESCE(max(id), 0) AS m FROM events")
        return r["m"] if r else 0

    def max_detection_id(self) -> int:
        r = _row(self._conn, "SELECT COALESCE(max(id), 0) AS m FROM detections")
        return r["m"] if r else 0

    def events_since(self, event_id: int, limit: int = 200) -> list[dict]:
        return _rows(self._conn, """
            SELECT e.*, d.det_count
            FROM events e
            LEFT JOIN (SELECT event_id, count(*) AS det_count FROM detections
                       GROUP BY event_id) d ON d.event_id = e.id
            WHERE e.id > %s ORDER BY e.id LIMIT %s
        """, (event_id, limit))

    def detections_since(self, det_id: int, limit: int = 100) -> list[dict]:
        return _rows(self._conn, """
            SELECT d.id, d.created_at, d.match_type, d.matched_value,
                   d.feed_name, e.src_ip, e.dst_ip, e.hostname, e.action AS event_action
            FROM detections d JOIN events e ON e.id = d.event_id
            WHERE d.id > %s ORDER BY d.id LIMIT %s
        """, (det_id, limit))

    def bucket_totals(self) -> dict:
        """Counts per bucket for events ingested today (UTC)."""
        rows = _rows(self._conn, """
            SELECT tag, action, count(*) AS n
            FROM events
            WHERE ts >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            GROUP BY tag, action
        """)
        totals = {b: 0 for b in BUCKET_ORDER}
        for r in rows:
            bucket = bucket_of({"tag": r["tag"], "action": r["action"]})
            totals[bucket] = totals.get(bucket, 0) + r["n"]
        totals["_total"] = sum(totals.values())
        return totals
