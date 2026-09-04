"""Postgres layer for Watchman collector: event inserts + detections.

Schema lives in shared/schema.py (applied idempotently by every service).
"""

from __future__ import annotations

import psycopg2
import psycopg2.extras

from shared.schema import apply_schema, conn_from_env  # noqa: F401  (re-export)

INSERT_EVENT = """
INSERT INTO events
    (ts, host, facility, severity, tag, raw, src_ip, dst_ip,
     src_port, dst_port, proto, action, msg, hostname)
VALUES (%(ts)s, %(host)s, %(facility)s, %(severity)s, %(tag)s, %(raw)s,
        %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s,
        %(proto)s, %(action)s, %(msg)s, %(hostname)s)
RETURNING id
"""

LOAD_IOCS = """
SELECT i.id, i.type, i.value, i.feed_id, f.name AS feed_name
FROM iocs i
JOIN feeds f ON f.id = i.feed_id
WHERE i.active AND f.deleted_at IS NULL
"""

INSERT_DETECTION = """
INSERT INTO detections (event_id, ioc_id, feed_id, feed_name, match_type, matched_value)
VALUES (%(event_id)s, %(ioc_id)s, %(feed_id)s, %(feed_name)s, %(match_type)s, %(matched_value)s)
ON CONFLICT (event_id, ioc_id, match_type) DO NOTHING
"""

GET_IOC_VERSION = "SELECT version FROM ioc_version WHERE id = 1"

GET_WATERMARK = "SELECT watermark_event_id FROM detector_state WHERE id = 1"

SET_WATERMARK = (
    "UPDATE detector_state SET watermark_event_id = %s WHERE id = 1"
)

RETRO_SCAN_EVENTS = """
SELECT * FROM events
WHERE id > %(watermark)s AND ts >= now() - (%(hours)s || ' hours')::interval
ORDER BY id
LIMIT %(limit)s
"""


class PostgresStore:
    """Store interface the collector depends on (events + detections)."""

    def __init__(self, conn):
        self._conn = conn

    def insert_event(self, ev: dict) -> int | None:
        row = dict(ev)
        try:
            with self._conn.cursor() as cur:
                cur.execute(INSERT_EVENT, row)
                event_id = cur.fetchone()[0]
            self._conn.commit()
            return event_id
        except psycopg2.Error:
            self._conn.rollback()
            raise

    def load_iocs(self) -> list[dict]:
        with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(LOAD_IOCS)
            return [dict(r) for r in cur.fetchall()]

    def insert_detections(self, event_id: int, detections: list[dict]) -> int:
        written = 0
        try:
            with self._conn.cursor() as cur:
                for d in detections:
                    cur.execute(INSERT_DETECTION, {
                        "event_id": event_id, **d,
                    })
                    written += 1
            self._conn.commit()
            return written
        except psycopg2.Error:
            self._conn.rollback()
            raise

    def get_ioc_version(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute(GET_IOC_VERSION)
            row = cur.fetchone()
            return row[0] if row else 0

    def get_watermark(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute(GET_WATERMARK)
            row = cur.fetchone()
            return row[0] if row else 0

    def set_watermark(self, event_id: int) -> None:
        with self._conn.cursor() as cur:
            cur.execute(SET_WATERMARK, (event_id,))
        self._conn.commit()

    def retro_scan_events(self, watermark: int, hours: int, limit: int = 5000) -> list[dict]:
        with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(RETRO_SCAN_EVENTS, {"watermark": watermark, "hours": hours,
                                            "limit": limit})
            return [dict(r) for r in cur.fetchall()]
