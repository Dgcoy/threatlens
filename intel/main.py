"""Watchman intel engine: scheduled feed pulls → IOC store.

Boot: apply schema, register default seed feeds (AUTO_SEED_FEEDS=1),
schedule each enabled feed by its auto_pull_minutes interval, then pull
every feed once shortly after start (with jitter).
"""

from __future__ import annotations

import os
import random
import signal
import sys
import time
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from feed_common import download_text
from feed_plain import pull_plain
from feed_stix import parse_bundle
from feed_taxii import poll_taxii
from registry import (
    bump_ioc_version,
    get_enabled_feeds,
    get_feed,
    get_pending_pull_requests,
    mark_pull_request_processed,
    record_pull,
    register_default_feeds,
    replace_feed_iocs,
)
from shared.schema import apply_schema, conn_from_env

USER_AGENT = os.environ.get("FEED_USER_AGENT", "Watchman/0.1")
DEFAULT_TIMEOUT = int(os.environ.get("STIX_TAXII_TIMEOUT", "30"))
STARTUP_DELAY_MIN = 5          # seconds after boot before first pull sweep
STARTUP_DELAY_MAX = 180


def pull_one(conn, feed: dict) -> int:
    """Pull a single feed and persist IOCs. Returns count written."""
    feed_type = feed["type"]
    try:
        if feed_type in ("plain", "csv"):
            iocs = pull_plain(feed, user_agent=USER_AGENT, timeout=DEFAULT_TIMEOUT)
        elif feed_type == "stix":
            text = download_text(feed["source_url"], user_agent=USER_AGENT,
                                 timeout=DEFAULT_TIMEOUT)
            iocs = parse_bundle(text)
        elif feed_type == "taxii":
            iocs = poll_taxii(feed, timeout=DEFAULT_TIMEOUT)
        else:
            raise ValueError(f"unknown feed type: {feed_type}")
    except Exception as exc:  # network/parse failures — record and continue
        record_pull(conn, feed["id"], "error", str(exc)[:500])
        raise

    written = replace_feed_iocs(conn, feed["id"], iocs)
    record_pull(conn, feed["id"], f"ok ({written})")
    bump_ioc_version(conn)
    return written


def sweep(conn) -> dict:
    """Pull every enabled feed once. Returns {feed_name: count}."""
    feeds = get_enabled_feeds(conn)
    results = {}
    for feed in feeds:
        try:
            results[feed["name"]] = pull_one(conn, feed)
        except Exception as exc:
            results[feed["name"]] = f"ERROR: {exc}"
    return results


def process_pull_requests(conn) -> int:
    """Honor on-demand pulls requested from the dashboard (feed_pull_requests)."""
    processed = 0
    for req in get_pending_pull_requests(conn):
        feed = get_feed(conn, req["feed_id"])
        if not feed or not feed.get("enabled") or feed.get("deleted_at"):
            mark_pull_request_processed(conn, req["id"], "skipped (feed unavailable)")
            processed += 1
            continue
        try:
            count = pull_one(conn, feed)
            mark_pull_request_processed(conn, req["id"], f"ok ({count})")
        except Exception as exc:
            mark_pull_request_processed(conn, req["id"], f"error: {str(exc)[:200]}")
        processed += 1
    return processed


def main() -> None:
    conn = conn_from_env()
    apply_schema(conn)

    if os.environ.get("AUTO_SEED_FEEDS", "1") == "1":
        created = register_default_feeds(conn)
        if created:
            print(f"registered default feeds: {', '.join(created)}", flush=True)

    if "--once" in sys.argv:
        results = sweep(conn)
        for name, count in results.items():
            print(f"  {name}: {count}", flush=True)
        conn.close()
        return

    sched = BackgroundScheduler(daemon=True)
    for feed in get_enabled_feeds(conn):
        minutes = int(feed.get("auto_pull_minutes") or 1440)
        sched.add_job(
            pull_one, IntervalTrigger(minutes=minutes, jitter=60),
            args=[conn, feed],
            id=f"feed-{feed['id']}", name=feed["name"],
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        print(f"scheduled '{feed['name']}' every {minutes}m", flush=True)
    sched.add_job(
        process_pull_requests, IntervalTrigger(seconds=30),
        args=[conn], id="pull-requests",
        max_instances=1, coalesce=True,
    )
    print("scheduled pull-request poller every 30s", flush=True)

    sched.start()

    # first sweep shortly after boot (randomized to spread outbound pulls)
    delay = random.uniform(STARTUP_DELAY_MIN, STARTUP_DELAY_MAX)
    print(f"first sweep in {delay:.0f}s", flush=True)
    time.sleep(delay)
    results = sweep(conn)
    for name, count in results.items():
        print(f"  first-sweep {name}: {count}", flush=True)

    def _stop(_signum, _frame):
        print("intel stopping", flush=True)
        sched.shutdown(wait=False)
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # keep alive; scheduled jobs run in background threads
    signal.pause()


if __name__ == "__main__":
    main()
