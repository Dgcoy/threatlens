# Architecture

Watchman is a four-service Docker Compose stack. Each service is a small
Python 3.12 image; all share an idempotent schema in `shared/schema.py` that
each service applies at startup.

```
                    ┌──────────────┐
 UDM ──syslog UDP──▶│  collector   │  syslog receiver (UDP 5514, host maps 514)
  :514               │  parser      │  normalize SRC=/DST= kernel/firewall lines,
                    │  matcher     │  DNS/DHCP hostnames; in-memory IOC match
                    └──────┬───────┘
                           │ events, detections
                    ┌──────▼───────┐
                    │  postgres    │  feeds, iocs, events, detections,
                    └──────┬───────┘  ioc_version, feed_pull_requests
                           ▲
                    ┌──────┴───────┐  scheduled pullers + on-demand queue
                    │   intel      │  plain / CSV / STIX 2.x / TAXII 2.x
                    └──────────────┘
                           ▲
                    ┌──────┴───────┐
 browser ──▶ api /  │     api      │  FastAPI: REST + WebSocket live stream,
 dashboard          └──────────────┘  static UI (zero CDN)
```

## Services

### collector
- UDP server (`syslog_server.py`) listening on 5514 (published as 514/udp).
- `unifi_parser.py` parses RFC3164 lines, handling the quirks of real UDM
  syslog: doubled hostname (`UDMPro UDMPro kernel: …`), device-id syslog tags
  (`<mac>,<model>-<fw>`), iptables `[rule-name]` log prefixes, and field
  extraction (`SRC`/`DST`/`SPT`/`DPT`/`PROTO`/`IN`/`OUT`). DNS query lines and
  DHCPACK lines yield hostname context for domain/URL IOC matching.
- `matcher.py` holds active IOCs in memory (exact IP set, CIDR containment
  list, domain suffix map). It refreshes when `ioc_version` changes and
  retro-scans recent events (watermark-tracked) so newly pulled feeds flag
  already-stored traffic.
- Event parsing is deliberately lossless: any line yields an event; only
  well-formed IP fields become `src_ip`/`dst_ip`.

### intel
- `registry.py` — feed CRUD, IOC upsert (`ON CONFLICT (feed_id,type,value)`),
  `ioc_version` bump, default seed feeds (ThreatFox, URLhaus, Feodo, Spamhaus).
- `feed_plain.py` — plain and CSV pullers with 1-based column mapping; comment
  rows (`#`/`;`) skipped; indicator types auto-detected.
- `feed_stix.py` — STIX 2.x bundle parsing: indicator patterns (`=` and
  `IN (...)`), bare observables, labels → tags, created/modified → seen window,
  external references → reference URL.
- `feed_taxii.py` — TAXII 2.0/2.1 collection polling via `taxii2-client`,
  optional Basic Auth.
- `main.py` — APScheduler with per-feed intervals (+ jitter) and a 30 s poller
  for on-demand pull requests queued from the dashboard.

### api
- FastAPI app with a pure-ASGI auth middleware (PIN gate; static assets open,
  API/pages gated). WS endpoints bypass the HTTP middleware and enforce auth
  in-handler.
- REST: stats, events (with `flows_only` filter for real traffic), detections
  (joined with event + IOC detail), feeds CRUD + pull queue, IOCs.
- WebSocket `/ws/events`: on connect sends a snapshot (bucket tallies + recent
  events/detections), then a 1 s poller streams `update` messages with new
  events (bucket-tagged), detections and bucket totals. Payloads are run
  through `_json_safe` because `WebSocket.send_json` uses plain `json.dumps`
  (no datetime encoder).
- UI: vanilla JS, dark theme, local assets only. Bucket taxonomy
  (`bucket_of`) lives in `queries.py` and is the single source of truth for
  the arena.

## Data model (PostgreSQL)

```
feeds(id, name, type plain|csv|stix|taxii, source_url, auth_json, parser_config,
      enabled, auto_pull_minutes, last_pull, last_status, last_error, deleted_at)
iocs(id, feed_id→feeds, type ip|cidr|domain|url, value, description, tags[],
     severity, reference, first_seen, last_seen, active)
events(id, ts, host, facility, severity, tag, raw, src_ip, dst_ip,
       src_port, dst_port, proto, action, msg, hostname)
detections(id, event_id→events, ioc_id→iocs, feed_id→feeds, feed_name,
           match_type src|dst|host, matched_value, created_at)
ioc_version(id=1, version)              -- collector refresh signal
detector_state(id=1, watermark_event_id) -- retro-scan cursor
feed_pull_requests(id, feed_id, requested_at, processed_at, status)
```

`feed_name` is snapshotted onto detections so deleting a feed never destroys
detection attribution.

## Live stream protocol (`/ws/events`)

```jsonc
// server → client
{"type": "snapshot", "buckets": {...totals, "_total": n},
 "events": [...recent, each with "bucket"], "detections": [...]}
{"type": "update", "events": [...new], "detections": [...new],
 "buckets": {...totals}}
// client → server
"ping"   // keepalive, every ~20 s
```

## Design notes / tradeoffs

- **UDP syslog is lossy by design** — acceptable for security telemetry.
- **Feed reality check**: real-world feeds have quirks (abuse.ch "recent" CSVs
  carry a comment-block header with quoted, space-prefixed values and the
  indicator in column 3). The parser is regression-tested against those
  formats; column mapping is configurable per feed in the UI.
- **Retro-scan** makes new feeds immediately useful against history without
  rescanning the whole table every refresh.
- The arena counts *all* ingested logs by category (kernel/system chatter
  included) — it's an ingestion view. Traffic tables default to
  `flows_only` (events with a source/destination).
