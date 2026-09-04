# Watchman 🛰️

**UDM syslog → threat intelligence → detection dashboard.**

Watchman listens to UniFi UDM / UDM Pro syslog, normalizes firewall and system
traffic events, matches source/destination IPs and hostnames against pluggable
open-source threat intelligence, and surfaces detections on a live, dark-themed
dashboard with full feed attribution.

```
UDM Pro ──syslog:514──▶ collector ──▶ PostgreSQL ◀── intel (plain/CSV/STIX/TAXII feeds)
                            │                      │
                            └── detections ◀── IOC matching ──▶ FastAPI + dashboard
```

## Features

- **Live ingestion arena** — Palo-Alto-style view: logs stream from the UDM
  source into category buckets (Firewall DROP/ACCEPT/Rule, IPS/DPIA, DNS, DHCP,
  WLAN, WAN, System, Kernel, Other) with particle animations, counters, share
  bars, an ingest ticker and a live events/min rate.
- **Detection engine** — in-memory IOC matcher (exact IP, CIDR containment,
  domain suffix, URL hostname) with retro-scan: new feed pulls re-check recent
  traffic. Every detection records *which feed* and *which indicator* fired.
- **Threat intel feeds** — add, delete, enable/disable from the UI:
  - **plain** line-per-indicator lists (IP / CIDR / domain / URL)
  - **CSV** with configurable column mapping
  - **STIX 2.x** bundles (JSON)
  - **TAXII 2.0 / 2.1** collections (with optional Basic Auth)
  - Bundled seed feeds: Abuse.ch ThreatFox, URLhaus, Feodo, Spamhaus DROP/EDROP
- **Dashboard** — stats cards, live traffic (flows only), detections with IOC
  detail modals (description, tags, severity, first/last seen, reference link),
  full event browser with search, IOC browser, feed management.
- **PIN-gated** — simple session gate (single PIN) suitable for a home network.
  Zero outbound requests from the UI (all assets bundled locally).

## Requirements

- Docker Engine + Docker Compose v2
- A UniFi UDM / UDM Pro with **Remote Logging** enabled
  (`Settings → System → Advanced → Remote Logging`) pointing at the host running
  the stack, UDP port 514. The UDM must be able to reach it.

## Quickstart

```bash
git clone https://github.com/Dgcoy/watchman.git
cd watchman

cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, APP_PIN (6-digit), SESSION_SECRET
#   python3 -c "import secrets; print(secrets.token_hex(32))"

docker compose up -d --build
```

Open `http://<host>:8000`, enter your PIN, and you're in. The intel service
auto-registers the four seed feeds and pulls them on its first sweep (~5–180 s
after boot).

### Point the UDM at it

In UniFi Network: **Settings → System → Advanced → Remote Logging** →
`<host-ip>:514` (UDP). Firewall/kernel traffic (SRC=/DST= lines), DNS and DHCP
events from the UDM then stream into the dashboard within seconds.

### Testing it without a UDM

```bash
pip install -r collector/requirements.txt   # psycopg2-binary
python3 scripts/inject_syslog.py --target <host>:514 --fixtures --count 20
```

## Feed configuration

Add feeds under **Feeds → Add feed**:

| Type | Fields |
|---|---|
| `plain` | Source URL (line per IOC; `#`/`;` comments skipped, types auto-detected) |
| `csv` | Source URL, delimiter, header row?, 1-based column numbers for value / description / tags / reference |
| `stix` | Bundle URL (STIX 2.x JSON) |
| `taxii` | Discovery URL, collection ID, TAXII version (2.0/2.1), optional username/password |

Each feed has a pull interval; **Pull now** queues an immediate pull that the
intel service processes within ~30 s. Deleting a feed soft-deletes it and
deactivates its IOCs; existing detections keep their feed attribution.

## Dashboard pages

| Route | Purpose |
|---|---|
| `/` | Live ingestion arena + stats + recent detections + live traffic |
| `/detections` | Filterable detection browser (feed + search), IOC detail modals |
| `/events` | Full event browser, search, "Flows only" toggle |
| `/feeds` | Feed management (add/delete/enable/pull-now) |
| `/iocs` | Threat-intelligence indicator browser |

## API (all JSON, PIN-gated)

```
GET  /api/stats            GET  /api/events[?q&since&flows_only&limit&offset]
GET  /api/events/{id}      GET  /api/detections[?feed_id&q&since&limit&offset]
GET  /api/detections/{id}  GET  /api/feeds
POST /api/feeds            PUT  /api/feeds/{id}        DELETE /api/feeds/{id}
POST /api/feeds/{id}/pull  GET  /api/iocs[?feed_id&type&q&limit&offset]
GET  /api/iocs/{id}        GET  /api/buckets
WS   /ws/events            (live stream: snapshot + bucket/event/detection updates)
POST /api/login            GET  /api/logout           GET  /api/health
```

## Development

```bash
pip install -r collector/requirements.txt -r intel/requirements.txt \
            -r api/requirements.txt pytest
pytest api/tests collector/tests intel/tests
```

## Configuration reference

| Env var | Service | Default | Purpose |
|---|---|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | all | `watchman` / — / `watchman` | database credentials |
| `APP_PIN` | api | — (required) | 6-digit dashboard PIN |
| `SESSION_SECRET` | api | — (required) | cookie signing secret |
| `SYSLOG_PORT` | collector | `5514` | UDP port inside the container (host maps 514→5514) |
| `SYSLOG_TIMEZONE` | collector | `UTC` | timezone of UDM timestamps (`America/Chicago`, …) |
| `IOC_REFRESH_SECONDS` | collector | `60` | how often the matcher polls for feed changes |
| `RETRO_SCAN_HOURS` | collector | `24` | retro-scan window after a feed pull |
| `PULL_INTERVAL_MINUTES` | intel | `60` | global feed-sweep cadence (per-feed overrides) |
| `FEED_USER_AGENT` | intel | `Watchman/0.1` | User-Agent sent to feed providers |
| `STIX_TAXII_TIMEOUT` | intel | `30` | feed download/poll timeout (s) |
| `AUTO_SEED_FEEDS` | intel | `1` | register the bundled seed feeds on boot |

## Security notes

- The dashboard is PIN-gated, but the PIN is a convenience gate for a home
  network — put the app behind your reverse proxy / VPN / auth layer if it will
  be reachable beyond your LAN.
- Syslog is received over **UDP 514** — lossy by design; fine for security
  telemetry.
- Feed credentials (e.g. TAXII Basic Auth) are stored in the local PostgreSQL
  database.
- The UI makes **zero outbound requests** — all CSS/JS is served by the app.

## Roadmap

- Charts (traffic / detections per feed), live WebSocket feed polish
- Discord/alerting integration for detections
- DNS-aware detection tuning, retention policy
- TAXII *server* export of your detection findings

## License

MIT — see [LICENSE](LICENSE).
