"""TAXII 2.x poller with a stubbed client module (no network)."""

import sys
import types

INDICATOR = {
    "type": "indicator",
    "id": "indicator--abc",
    "pattern": "[ipv4-addr:value = '203.0.113.66']",
    "description": "from taxii",
    "labels": ["malicious-activity"],
}


def _install_fake_taxii():
    v20 = types.ModuleType("taxii2client.v20")

    class FakeCollection:
        id = "col-1"

        def get_objects(self, **kwargs):
            return {"objects": [INDICATOR]}

    class FakeApiRoot:
        collections = [FakeCollection()]

    class FakeServer:
        def __init__(self, url, user=None, password=None):
            self.url = url
            self.user = user
            self.password = password
            self.api_roots = [FakeApiRoot()]

    v20.Server = FakeServer
    v20.Collection = FakeCollection
    pkg = types.ModuleType("taxii2client")
    pkg.v20 = v20
    sys.modules["taxii2client"] = pkg
    sys.modules["taxii2client.v20"] = v20


def test_poll_taxii_returns_iocs():
    _install_fake_taxii()
    from feed_taxii import poll_taxii

    feed = {
        "source_url": "https://taxii.example/taxii/",
        "parser_config": {"collection_id": "col-1", "version": "2.0"},
        "auth_json": {"username": "guest", "password": "guest"},
    }
    iocs = poll_taxii(feed)
    assert len(iocs) == 1
    assert iocs[0]["value"] == "203.0.113.66"
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["description"] == "from taxii"


def test_poll_taxii_unknown_collection_raises():
    _install_fake_taxii()
    from feed_taxii import poll_taxii

    feed = {
        "source_url": "https://taxii.example/taxii/",
        "parser_config": {"collection_id": "nope", "version": "2.0"},
    }
    try:
        poll_taxii(feed)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "not found" in str(exc)


def test_install_browser_ua_injects_session_header(monkeypatch):
    """The TAXII client must send a browser-like User-Agent (OTX-style WAFs
    404 non-browser UAs)."""
    import requests as _requests
    from feed_taxii import TAXII_USER_AGENT, _install_browser_ua

    monkeypatch.setattr(_requests, "Session", _requests.Session)
    _install_browser_ua()
    s = _requests.Session()
    assert s.headers.get("User-Agent") == TAXII_USER_AGENT


def test_get_objects_with_retry_retries_then_succeeds():
    from feed_taxii import _get_objects_with_retry

    calls = {"n": 0}

    class FlakyColl:
        def get_objects(self):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("transient")
            return {"objects": [{"type": "indicator"}]}

    env = _get_objects_with_retry(FlakyColl(), attempts=3)
    assert env["objects"][0]["type"] == "indicator"
    assert calls["n"] == 3
