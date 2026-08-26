"""Shared schema + connection helpers for all ThreatLens services.

Every service image gets `shared/` copied in and applies the idempotent
schema at startup, so the platform self-provisions on first boot.
"""

from __future__ import annotations

import os

import psycopg2

SCHEMA = """
CREATE TABLE IF NOT EXISTS feeds (
    id serial PRIMARY KEY,
    name text UNIQUE NOT NULL,
    type text NOT NULL CHECK (type IN ('plain','csv','stix','taxii')),
    source_url text,
    auth_json jsonb,
    parser_config jsonb,
    enabled boolean NOT NULL DEFAULT true,
    auto_pull_minutes integer NOT NULL DEFAULT 1440,
    last_pull timestamptz,
    last_status text,
    last_error text,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iocs (
    id bigserial PRIMARY KEY,
    feed_id integer REFERENCES feeds(id) ON DELETE CASCADE,
    type text NOT NULL CHECK (type IN ('ip','cidr','domain','url')),
    value text NOT NULL,
    description text,
    tags text[],
    severity text,
    reference text,
    first_seen timestamptz,
    last_seen timestamptz,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (feed_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs (type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs (active);

CREATE TABLE IF NOT EXISTS events (
    id bigserial PRIMARY KEY,
    ts timestamptz NOT NULL,
    host text,
    facility text,
    severity text,
    tag text,
    raw text,
    src_ip inet,
    dst_ip inet,
    src_port integer,
    dst_port integer,
    proto text,
    action text,
    msg text
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events (dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events (action);

CREATE TABLE IF NOT EXISTS detections (
    id bigserial PRIMARY KEY,
    event_id bigint REFERENCES events(id) ON DELETE CASCADE,
    ioc_id bigint REFERENCES iocs(id) ON DELETE SET NULL,
    feed_id integer REFERENCES feeds(id) ON DELETE SET NULL,
    feed_name text,
    match_type text NOT NULL CHECK (match_type IN ('src','dst','host')),
    matched_value text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (event_id, ioc_id, match_type)
);
CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_feed_id ON detections (feed_id);
CREATE INDEX IF NOT EXISTS idx_detections_matched_value ON detections (matched_value);

-- bumped by intel after every successful feed pull; collector polls it to
-- know when to refresh its in-memory IOC snapshot
CREATE TABLE IF NOT EXISTS ioc_version (
    id integer PRIMARY KEY CHECK (id = 1),
    version bigint NOT NULL DEFAULT 0
);
INSERT INTO ioc_version (id, version) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

-- collector detection-engine watermark (retro-scan cursor)
CREATE TABLE IF NOT EXISTS detector_state (
    id integer PRIMARY KEY CHECK (id = 1),
    watermark_event_id bigint NOT NULL DEFAULT 0
);
INSERT INTO detector_state (id, watermark_event_id) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

-- on-demand feed pulls requested from the API dashboard; intel polls these
CREATE TABLE IF NOT EXISTS feed_pull_requests (
    id bigserial PRIMARY KEY,
    feed_id integer REFERENCES feeds(id) ON DELETE CASCADE,
    requested_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    status text
);
CREATE INDEX IF NOT EXISTS idx_pull_requests_pending
    ON feed_pull_requests (processed_at) WHERE processed_at IS NULL;
"""

# migrations for tables created before a column/constraint existed (idempotent)
ALTERS = """
ALTER TABLE events ADD COLUMN IF NOT EXISTS hostname text;
ALTER TABLE detections DROP CONSTRAINT IF EXISTS detections_match_type_check;
ALTER TABLE detections ADD CONSTRAINT detections_match_type_check
    CHECK (match_type IN ('src','dst','host'));
"""


def conn_from_env() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        user=os.environ.get("POSTGRES_USER", "threatlens"),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
        dbname=os.environ.get("POSTGRES_DB", "threatlens"),
    )


def apply_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
        cur.execute(ALTERS)
    conn.commit()
