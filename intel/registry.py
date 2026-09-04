"""Feed registry access for the intel engine (thin SQL over shared schema)."""

from __future__ import annotations

from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

UPSERT_IOC = """
INSERT INTO iocs (feed_id, type, value, description, tags, severity, reference,
                  first_seen, last_seen)
VALUES (%(feed_id)s, %(type)s, %(value)s, %(description)s, %(tags)s,
        %(severity)s, %(reference)s, %(first_seen)s, %(last_seen)s)
ON CONFLICT (feed_id, type, value) DO UPDATE SET
    description = EXCLUDED.description,
    tags = EXCLUDED.tags,
    severity = EXCLUDED.severity,
    reference = EXCLUDED.reference,
    first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
    active = true
"""


def _rows(conn, sql, params=()) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def get_enabled_feeds(conn) -> list[dict]:
    return _rows(
        conn,
        "SELECT * FROM feeds WHERE enabled AND deleted_at IS NULL ORDER BY id",
    )


def get_feed(conn, feed_id: int) -> dict | None:
    rows = _rows(conn, "SELECT * FROM feeds WHERE id = %s", (feed_id,))
    return rows[0] if rows else None


def record_pull(conn, feed_id: int, status: str, error: str | None = None,
                now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE feeds SET last_pull = %s, last_status = %s, last_error = %s "
            "WHERE id = %s",
            (now, status, error, feed_id),
        )
        cur.execute(
            "INSERT INTO feed_logs (feed_id, ts, level, message) "
            "VALUES (%s, %s, %s, %s)",
            (feed_id, now,
             "error" if error else "info",
             f"pull {'failed' if error else 'ok'}: {error or status}"),
        )
    conn.commit()


def replace_feed_iocs(conn, feed_id: int, iocs: list[dict],
                      now: datetime | None = None) -> int:
    """Upsert the feed's IOCs. Returns number written.

    `iocs` is a list of dicts with keys: type, value, description, tags,
    severity, reference. first_seen/last_seen default to `now`.
    """
    now = now or datetime.now(timezone.utc)
    written = 0
    with conn.cursor() as cur:
        for ioc in iocs:
            cur.execute(UPSERT_IOC, {
                "feed_id": feed_id,
                "type": ioc["type"],
                "value": ioc["value"],
                "description": ioc.get("description"),
                "tags": ioc.get("tags") or None,
                "severity": ioc.get("severity"),
                "reference": ioc.get("reference"),
                "first_seen": ioc.get("first_seen") or now,
                "last_seen": ioc.get("last_seen") or now,
            })
            written += 1
    conn.commit()
    return written


def bump_ioc_version(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE ioc_version SET version = version + 1 WHERE id = 1")
    conn.commit()


def get_pending_pull_requests(conn, limit: int = 20) -> list[dict]:
    return _rows(
        conn,
        """SELECT id, feed_id FROM feed_pull_requests
           WHERE processed_at IS NULL ORDER BY id LIMIT %s""",
        (limit,),
    )


def mark_pull_request_processed(conn, req_id: int, status: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE feed_pull_requests SET processed_at = now(), status = %s WHERE id = %s",
            (status, req_id),
        )
    conn.commit()


def register_default_feeds(conn) -> list[str]:
    """Idempotently register the bundled open-source seed feeds.

    Returns the names of feeds that were created (or already existed).
    """
    defaults = [
        {
            "name": "Abuse.ch ThreatFox (recent)",
            "type": "csv",
            "source_url": "https://threatfox.abuse.ch/export/csv/recent/",
            # verified format (Aug 2026): comment-block header, columns
            # first_seen_utc, ioc_id, ioc_value, type, threat_type, malware, …
            "parser_config": {
                "has_header": False, "value_column": 3, "delimiter": ",",
                "description_column": 6, "tags_column": 5,
            },
            "auto_pull_minutes": 60,
        },
        {
            "name": "Abuse.ch URLhaus (recent)",
            "type": "csv",
            "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            # verified format (Aug 2026): comment-block header, columns
            # id, dateadded, url, url_status, last_online, threat, tags,
            # urlhaus_link, reporter
            "parser_config": {
                "has_header": False, "value_column": 3, "delimiter": ",",
                "description_column": 6, "tags_column": 7, "reference_column": 8,
            },
            "auto_pull_minutes": 60,
        },
        {
            "name": "Abuse.ch Feodo IP blocklist",
            "type": "plain",
            "source_url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            "parser_config": {},
            "auto_pull_minutes": 360,
        },
        {
            "name": "Spamhaus DROP/EDROP",
            "type": "plain",
            "source_url": "https://www.spamhaus.org/drop/drop.txt",
            "parser_config": {},
            "auto_pull_minutes": 360,
        },
    ]
    created = []
    with conn.cursor() as cur:
        for d in defaults:
            # upsert: refresh source/config so feed definitions self-heal on
            # boot (last_pull/status preserved). UI-managed edits may set a
            # 'managed' flag later to opt out.
            cur.execute(
                """INSERT INTO feeds (name, type, source_url, parser_config, auto_pull_minutes)
                   VALUES (%(name)s, %(type)s, %(source_url)s,
                           %(parser_config)s, %(auto_pull_minutes)s)
                   ON CONFLICT (name) WHERE (deleted_at IS NULL) DO UPDATE SET
                       type = EXCLUDED.type,
                       source_url = EXCLUDED.source_url,
                       parser_config = EXCLUDED.parser_config,
                       auto_pull_minutes = EXCLUDED.auto_pull_minutes
                   RETURNING name""",
                {
                    "name": d["name"],
                    "type": d["type"],
                    "source_url": d["source_url"],
                    "parser_config": psycopg2.extras.Json(d["parser_config"]),
                    "auto_pull_minutes": d["auto_pull_minutes"],
                },
            )
            row = cur.fetchone()
            if row:
                created.append(row[0])
    conn.commit()
    return created
