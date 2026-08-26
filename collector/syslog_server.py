"""ThreatLens collector: UDP syslog receiver + detection engine.

Listens on 0.0.0.0:SYSLOG_PORT (host maps 514/udp → 5514/udp),
parses each datagram with unifi_parser, persists events, and matches
them against an in-memory IOC snapshot (refreshed on ioc_version bumps
from the intel engine). Retro-scans recent events when new IOCs land.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import threading
import time

from unifi_parser import parse_syslog_line


class SyslogServer:
    def __init__(self, port: int, store, tz: str = "UTC",
                 ioc_refresh_seconds: int = 60,
                 retro_scan_hours: int = 24,
                 retro_scan_limit: int = 5000):
        self.port = port
        self.store = store
        self.tz = tz
        self.ioc_refresh_seconds = ioc_refresh_seconds
        self.retro_scan_hours = retro_scan_hours
        self.retro_scan_limit = retro_scan_limit
        self._running = threading.Event()
        self._sock = None
        self.stats = {"received": 0, "parsed": 0, "stored": 0,
                      "detections": 0, "errors": 0}
        self._matcher = None      # lazy-imported IocMatcher
        self._ioc_version = -1
        self._last_refresh = 0.0
        self._watermark = None

    # ---- IOC snapshot management ----
    def _refresh_iocs(self) -> None:
        try:
            from matcher import IocMatcher
            rows = self.store.load_iocs()
            if self._matcher is None:
                self._matcher = IocMatcher()
            n = self._matcher.load_rows(rows)
            self._ioc_version = self.store.get_ioc_version()
            self._last_refresh = time.time()
            print(f"collector: loaded {n} IOC refs (version {self._ioc_version})",
                  flush=True)
        except Exception as exc:
            print(f"collector: IOC refresh failed: {exc}", flush=True)

    def _maybe_refresh(self) -> None:
        if time.time() - self._last_refresh < self.ioc_refresh_seconds:
            return
        try:
            version = self.store.get_ioc_version()
            if version != self._ioc_version:
                print(f"collector: ioc_version {self._ioc_version} → {version}; reloading",
                      flush=True)
                self._refresh_iocs()
                self._retro_scan()
        except Exception as exc:
            print(f"collector: version poll failed: {exc}", flush=True)

    def _retro_scan(self) -> None:
        """Match NEW IOCs against already-stored events (watermark-based)."""
        if self._matcher is None:
            return
        if self._watermark is None:
            self._watermark = self.store.get_watermark()
        scanned = 0
        detections = 0
        while True:
            events = self.store.retro_scan_events(
                self._watermark, self.retro_scan_hours, self.retro_scan_limit)
            if not events:
                break
            for ev in events:
                hits = self._matcher.match_event(ev)
                if hits:
                    detections += self.store.insert_detections(ev["id"], hits)
                self._watermark = max(self._watermark, ev["id"])
                scanned += 1
            if len(events) < self.retro_scan_limit:
                break
        self.store.set_watermark(self._watermark)
        if scanned:
            print(f"collector: retro-scan {scanned} events, {detections} detections",
                  flush=True)

    # ---- datagram handling ----
    def _handle(self, data: bytes) -> None:
        self.stats["received"] += 1
        try:
            text = data.decode("utf-8", errors="replace")
            ev = parse_syslog_line(text, tz=self.tz)
            if ev is None:
                return
            self.stats["parsed"] += 1
            event_id = self.store.insert_event(ev)
            self.stats["stored"] += 1
            if event_id and self._matcher is not None:
                hits = self._matcher.match_event(ev)
                if hits:
                    n = self.store.insert_detections(event_id, hits)
                    self.stats["detections"] += n
        except Exception:
            self.stats["errors"] += 1

    # ---- server loop ----
    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.settimeout(1.0)
        self._running.set()
        print(f"collector listening on udp {self._sock.getsockname()} (tz={self.tz})",
              flush=True)
        while self._running.is_set():
            try:
                data, _addr = self._sock.recvfrom(65535)
                self._handle(data)
            except socket.timeout:
                self._maybe_refresh()
                continue
            except OSError:
                break

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def main() -> None:
    # lazy imports so unit tests of the server loop don't need psycopg2
    from db import PostgresStore, apply_schema, conn_from_env

    port = int(os.environ.get("SYSLOG_PORT", "5514"))
    tz = os.environ.get("SYSLOG_TIMEZONE", "UTC")
    ioc_refresh = int(os.environ.get("IOC_REFRESH_SECONDS", "60"))
    retro_hours = int(os.environ.get("RETRO_SCAN_HOURS", "24"))

    conn = conn_from_env()
    apply_schema(conn)
    store = PostgresStore(conn)

    server = SyslogServer(port, store, tz=tz,
                          ioc_refresh_seconds=ioc_refresh,
                          retro_scan_hours=retro_hours)

    def _shutdown(_signum, _frame):
        server.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server._refresh_iocs()      # load IOC snapshot before serving
        server.serve_forever()
    finally:
        conn.close()
    print(f"collector stopped: {server.stats}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
