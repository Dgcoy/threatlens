"""API route tests with a fake repo (no Postgres)."""

import pytest
import requests
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from datetime import datetime, timezone
from types import SimpleNamespace

from app import WSManager, app
from queries import bucket_of


class FakeRepo:
    def stats(self):
        return {"events_today": 12, "events_total": 3400, "detections_24h": 3,
                "detections_total": 4, "active_feeds": 4, "feeds_total": 4,
                "iocs_active": 20350, "iocs_total": 20350}

    def events(self, q=None, since=None, limit=50, offset=0, flows_only=False):
        return [{"id": 1, "ts": "2026-08-26T06:00:01+00:00", "host": "UDM",
                 "tag": "kernel", "src_ip": "192.168.1.42", "dst_ip": "1.1.1.1",
                 "src_port": 5353, "dst_port": 5353, "proto": "UDP",
                 "action": "FW-DROP", "hostname": None, "msg": "x", "raw": "r",
                 "det_count": 1}][:limit]

    def event(self, event_id):
        return {"id": event_id, "ts": "2026-08-26T06:00:01+00:00", "host": "UDM",
                "tag": "kernel", "src_ip": "192.168.1.42", "dst_ip": "1.1.1.1",
                "action": "FW-DROP", "hostname": None, "raw": "raw line",
                "detections": [{"id": 1, "match_type": "src",
                                "matched_value": "192.168.1.42", "feed_name": "X"}]}

    def detections(self, feed_id=None, q=None, since=None, limit=50, offset=0):
        return [{"id": 1, "created_at": "2026-08-26T06:00:02+00:00",
                 "match_type": "src", "matched_value": "192.168.1.42",
                 "feed_name": "TestFeed", "feed_id": 1, "event_id": 1,
                 "event_ts": "2026-08-26T06:00:01+00:00", "event_action": "FW-DROP",
                 "src_ip": "192.168.1.42", "dst_ip": "1.1.1.1", "hostname": None,
                 "event_tag": "kernel", "src_port": None, "dst_port": None,
                 "proto": "UDP", "ioc_description": "c2", "ioc_tags": ["botnet"],
                 "ioc_severity": None, "ioc_reference": "https://x", 
                 "ioc_first_seen": None, "ioc_last_seen": None, "ioc_value": "192.168.1.42"}][:limit]

    def detection(self, det_id):
        return {"id": det_id, "match_type": "src", "matched_value": "192.168.1.42",
                "feed_name": "TestFeed", "feed_id": 1, "event_id": 1,
                "event_raw": "raw", "event_ts": "t", "event_host": "UDM",
                "event_action": "FW-DROP", "src_ip": "192.168.1.42",
                "dst_ip": "1.1.1.1", "hostname": None, "src_port": None,
                "dst_port": None, "proto": "UDP", "event_tag": "kernel",
                "ioc_description": "c2", "ioc_tags": ["botnet"],
                "ioc_severity": None, "ioc_reference": None,
                "ioc_first_seen": None, "ioc_last_seen": None,
                "ioc_value": "192.168.1.42", "ioc_type": "ip"}

    def feeds(self):
        return [{"id": 1, "name": "TestFeed", "type": "plain",
                 "source_url": "https://x", "auth_json": None,
                 "parser_config": {}, "enabled": True, "auto_pull_minutes": 60,
                 "last_pull": None, "last_status": "ok (1)", "last_error": None,
                 "deleted_at": None, "created_at": "t", "ioc_count": 1}]

    def feed(self, feed_id):
        return {"id": feed_id, "name": "TestFeed", "type": "plain",
                "source_url": "https://x", "enabled": True, "deleted_at": None}

    def create_feed(self, data):
        if not data.get("name"):
            raise ValueError("name is required")
        if data.get("type") not in ("plain", "csv", "stix", "taxii"):
            raise ValueError("type must be one of plain, csv, stix, taxii")
        return {"id": 99, "name": data["name"], "type": data["type"]}

    def update_feed(self, feed_id, data):
        return {"id": feed_id, "enabled": data.get("enabled", True)}

    def delete_feed(self, feed_id):
        return True

    def request_pull(self, feed_id):
        return True

    def iocs(self, feed_id=None, ioc_type=None, q=None, limit=50, offset=0):
        return [{"id": 1, "type": "ip", "value": "192.168.1.42",
                 "description": "c2", "tags": ["botnet"], "severity": None,
                 "reference": None, "first_seen": None, "last_seen": None,
                 "active": True, "created_at": "t", "feed_name": "TestFeed"}][:limit]

    def ioc(self, ioc_id):
        return {"id": ioc_id, "type": "ip", "value": "192.168.1.42",
                "description": "c2", "tags": ["botnet"], "feed_name": "TestFeed"}

    def feed_logs(self, feed_id, limit=50):
        return [{"id": 1, "feed_id": feed_id, "ts": "2026-08-26T06:00:00+00:00",
                 "level": "info", "message": "pull ok: ok (1704)"},
                {"id": 2, "feed_id": feed_id, "ts": "2026-08-26T05:00:00+00:00",
                 "level": "error", "message": "pull failed: timeout"}]

    # ---- live stream fakes ----
    def max_event_id(self):
        return 100

    def max_detection_id(self):
        return 7

    def events_since(self, event_id, limit=200):
        return [{"id": event_id + 1,
                 "ts": datetime(2026, 8, 26, 6, 0, 1, tzinfo=timezone.utc),
                 "host": "UDM", "tag": "kernel", "src_ip": "192.168.1.42",
                 "dst_ip": "1.1.1.1", "src_port": 5353, "dst_port": 5353,
                 "proto": "UDP", "action": "FW-DROP", "hostname": None,
                 "msg": "x", "raw": "r", "det_count": 0}]

    def detections_since(self, det_id, limit=100):
        return [{"id": det_id + 1,
                 "created_at": datetime(2026, 8, 26, 6, 0, 2, tzinfo=timezone.utc),
                 "match_type": "src", "matched_value": "192.168.1.42",
                 "feed_name": "TestFeed", "src_ip": "192.168.1.42",
                 "dst_ip": "1.1.1.1", "hostname": None,
                 "event_action": "FW-DROP"}]

    def bucket_totals(self):
        return {"Firewall · DROP": 50, "Firewall · ACCEPT": 10,
                "Firewall · Rule": 0, "IPS / DPIA": 0, "DNS": 5, "DHCP": 2,
                "WLAN": 0, "WAN": 0, "System": 0, "Kernel": 0, "Other": 0,
                "_total": 67}


@pytest.fixture
def client():
    app.state.repo = FakeRepo()
    app.state.ws_manager = WSManager()
    # no context manager → lifespan (DB connect) is skipped
    return TestClient(app)


def _login(client):
    r = client.post("/api/login", json={"pin": "123456"})
    assert r.status_code == 200
    return r


def test_health_open(client):
    assert client.get("/api/health").status_code == 200


def test_api_requires_auth(client):
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/feeds").status_code == 401


def test_pages_redirect_when_unauthenticated(client):
    for path in ("/", "/detections", "/events", "/feeds", "/iocs"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["location"]


def test_static_assets_load_without_auth(client):
    # login page must be able to fetch css/js before a cookie exists
    for path in ("/static/js/app.js", "/static/css/app.css"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(
            "text/javascript" if path.endswith("js") else "text/css")


def test_login_wrong_pin(client):
    assert client.post("/api/login", json={"pin": "000000"}).status_code == 401


def test_login_sets_cookie_and_api_works(client):
    r = _login(client)
    assert "tl_auth" in r.cookies
    assert client.get("/api/stats").status_code == 200
    assert client.get("/").status_code == 200


def test_logout_clears(client):
    _login(client)
    client.get("/api/logout")
    assert client.get("/api/stats").status_code == 401


def test_stats_shape(client):
    _login(client)
    s = client.get("/api/stats").json()
    assert s["iocs_active"] == 20350
    assert "detections_24h" in s


def test_events_list(client):
    _login(client)
    evs = client.get("/api/events?limit=5").json()
    assert len(evs) == 1
    assert evs[0]["src_ip"] == "192.168.1.42"
    # flows_only must be accepted (dashboard live-traffic panel)
    assert client.get("/api/events?flows_only=1").status_code == 200


def test_create_feed_validation(client):
    _login(client)
    r = client.post("/api/feeds", json={"type": "plain", "source_url": "https://x"})
    assert r.status_code == 400          # missing name
    assert "name" in r.json()["detail"].lower()
    r = client.post("/api/feeds", json={"name": "ok", "source_url": "https://x"})
    assert r.status_code == 400          # missing type
    r = client.post("/api/feeds", json={"name": "ok", "type": "bogus", "source_url": "https://x"})
    assert r.status_code == 400          # bad type


def test_create_feed_duplicate_name_returns_400(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(client.app.state.repo, "create_feed",
                        lambda data: (_ for _ in ()).throw(ValueError("a feed named 'X' already exists")))
    r = client.post("/api/feeds", json={"name": "X", "type": "plain", "source_url": "https://x.example/i.txt"})
    assert r.status_code == 400
    assert "already exists" in r.json()["detail"]


def test_feed_logs_endpoint(client):
    _login(client)
    logs = client.get("/api/feeds/1/logs").json()
    assert len(logs) == 2
    assert logs[0]["level"] == "info"
    assert "pull ok" in logs[0]["message"]
    assert logs[1]["level"] == "error"


def test_create_feed_ok(client):
    _login(client)
    r = client.post("/api/feeds", json={"name": "My feed", "type": "plain",
                                        "source_url": "https://example.com/list.txt"})
    assert r.status_code == 200
    assert r.json()["id"] == 99


def test_delete_and_pull_routes(client):
    _login(client)
    assert client.delete("/api/feeds/1").json()["ok"] is True
    assert client.post("/api/feeds/1/pull").json()["queued"] is True


def test_iocs_list(client):
    _login(client)
    iocs = client.get("/api/iocs?type=ip").json()
    assert iocs[0]["type"] == "ip"


# ---- bucket taxonomy ----

def test_bucket_of_firewall_actions():
    assert bucket_of({"tag": "kernel", "action": "FW-DROP"}) == "Firewall · DROP"
    assert bucket_of({"tag": "kernel", "action": "FW-ACCEPT"}) == "Firewall · ACCEPT"
    assert bucket_of({"tag": "kernel", "action": "DPIA-BLOCK"}) == "IPS / DPIA"
    assert bucket_of({"tag": "kernel", "action": "IPS-ALERT"}) == "IPS / DPIA"


def test_bucket_of_rule_name_without_tag():
    # real UDM lines: no tag, action = iptables rule name
    assert bucket_of({"tag": None, "action": "DMZ_WAN-A-10000"}) == "Firewall · Rule"


def test_bucket_of_daemons():
    assert bucket_of({"tag": "dnsmasq", "action": None}) == "DNS"
    assert bucket_of({"tag": "dnsmasq-dhcp", "action": None}) == "DHCP"
    assert bucket_of({"tag": "hostapd", "action": None}) == "WLAN"
    assert bucket_of({"tag": "pppd", "action": None}) == "WAN"
    assert bucket_of({"tag": "syslog", "action": None}) == "System"
    assert bucket_of({"tag": "kernel", "action": None}) == "Kernel"


def test_bucket_of_fallbacks():
    assert bucket_of({"tag": None, "action": None}) == "Other"
    assert bucket_of({}) == "Other"
    assert bucket_of({"tag": "something-new", "action": None}) == "Other"


# ---- live ingestion API ----

def test_buckets_endpoint(client):
    _login(client)
    r = client.get("/api/buckets")
    assert r.status_code == 200
    body = r.json()
    assert body["buckets"]["Firewall · DROP"] == 50
    assert body["buckets"]["_total"] == 67
    assert "Firewall · DROP" in body["order"]


def test_ws_requires_auth(client):
    # without login cookie the upgrade must be rejected (either at connect
    # or on the first frame) — the socket must never deliver a snapshot
    with pytest.raises((Exception, WebSocketDisconnect)):
        with client.websocket_connect("/ws/events") as ws:
            ws.receive_json()


def test_ws_snapshot_after_login(client):
    _login(client)
    with client.websocket_connect("/ws/events") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert msg["buckets"]["Firewall · DROP"] == 50
        assert msg["events"][0]["bucket"] == "Firewall · DROP"
        assert len(msg["detections"]) == 1


# ---- TAXII discovery ----

def _fake_http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.HTTPError(response=resp)


def test_taxii_discover_v21(client, monkeypatch):
    _login(client)
    seen = {}

    def fake_get(url, headers=None, auth=None, timeout=None):
        seen[url] = headers
        ok = lambda: None  # noqa: E731  (raise_for_status no-op)
        if url.endswith("/taxii/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "default": "https://otx.example/taxii/root",
                "api_roots": ["https://otx.example/taxii/root"]}, raise_for_status=ok)
        if url.endswith("/collections/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "collections": [{"id": "7f9137a7-59ff-4fc6-957a-a90cc66c91b5",
                                 "title": "Data feed for user: AlienVault",
                                 "description": "d", "can_read": True}]}, raise_for_status=ok)
        return SimpleNamespace(status_code=200, json=lambda: {}, raise_for_status=ok)

    monkeypatch.setattr("taxii_discover.requests.get", fake_get)
    r = client.post("/api/taxii/discover",
                    json={"discovery_url": "https://otx.example/taxii/"})
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "2.1"
    assert body["collections"][0]["id"] == "7f9137a7-59ff-4fc6-957a-a90cc66c91b5"
    # TAXII 2.1 accept header must be sent
    assert "2.1" in seen["https://otx.example/taxii/"]["Accept"]


def test_taxii_discover_falls_back_to_v20(client, monkeypatch):
    _login(client)

    def fake_get(url, headers=None, auth=None, timeout=None):
        if headers["Accept"].endswith("2.1"):
            raise _fake_http_error(406)
        ok = lambda: None  # noqa: E731
        if url.endswith("/taxii/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "api_roots": ["https://old.example/taxii/root"]}, raise_for_status=ok)
        if url.endswith("/collections/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "collections": [{"id": "col-20", "title": "Legacy"}]}, raise_for_status=ok)
        return SimpleNamespace(status_code=200, json=lambda: {}, raise_for_status=ok)

    monkeypatch.setattr("taxii_discover.requests.get", fake_get)
    r = client.post("/api/taxii/discover",
                    json={"discovery_url": "https://old.example/taxii/"})
    assert r.status_code == 200
    assert r.json()["version"] == "2.0"
    assert r.json()["collections"][0]["id"] == "col-20"


def test_taxii_discover_requires_url(client):
    _login(client)
    assert client.post("/api/taxii/discover", json={}).status_code == 400


def test_taxii_discover_non_json_body_returns_400(client):
    _login(client)
    r = client.post("/api/taxii/discover", content=b"garbage",
                    headers={"Content-Type": "text/plain"})
    assert r.status_code == 400
    assert "invalid request body" in r.json()["detail"]


def test_taxii_discover_retries_transient_errors(client, monkeypatch):
    """Timeouts/5xx are retried with backoff, then succeed."""
    _login(client)
    calls = {"n": 0}
    ok = lambda: None  # noqa: E731

    def fake_get(url, headers=None, auth=None, timeout=None):
        calls["n"] += 1
        if url.endswith("/taxii/"):
            if calls["n"] < 3:
                raise requests.exceptions.ReadTimeout("read timeout")
            return SimpleNamespace(status_code=200, json=lambda: {
                "api_roots": ["https://slow.example/taxii/root"]}, raise_for_status=ok)
        if url.endswith("/collections/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "collections": [{"id": "c1", "title": "Slow OK"}]}, raise_for_status=ok)
        return SimpleNamespace(status_code=200, json=lambda: {}, raise_for_status=ok)

    monkeypatch.setattr("taxii_discover.requests.get", fake_get)
    r = client.post("/api/taxii/discover",
                    json={"discovery_url": "https://slow.example/taxii/"})
    assert r.status_code == 200
    assert r.json()["collections"][0]["id"] == "c1"
    assert calls["n"] >= 3     # discovery was retried


def test_taxii_discover_reports_root_errors(client, monkeypatch):
    """If collections can't be reached, the response includes errors."""
    _login(client)
    ok = lambda: None  # noqa: E731

    def fake_get(url, headers=None, auth=None, timeout=None):
        if url.endswith("/taxii/"):
            return SimpleNamespace(status_code=200, json=lambda: {
                "api_roots": ["https://dead.example/taxii/root"]}, raise_for_status=ok)
        raise requests.exceptions.ConnectionError("no route to host")

    monkeypatch.setattr("taxii_discover.requests.get", fake_get)
    r = client.post("/api/taxii/discover",
                    json={"discovery_url": "https://dead.example/taxii/"})
    assert r.status_code == 400
    assert "could not reach collections" in r.json()["detail"]
