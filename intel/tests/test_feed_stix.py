"""STIX bundle parsing."""

import json

from feed_stix import extract_pattern_values, parse_bundle

BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-1111-1111-1111-111111111111",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--22222222-2222-2222-2222-222222222222",
            "pattern": "[ipv4-addr:value = '203.0.113.66']",
            "description": "C2 server used by EvilGroup",
            "labels": ["malicious-activity", "c2"],
            "created": "2026-08-01T00:00:00.000Z",
            "modified": "2026-08-10T00:00:00.000Z",
            "external_references": [{"url": "https://example.com/report/1"}],
        },
        {
            "type": "indicator",
            "id": "indicator--33333333-3333-3333-3333-333333333333",
            "pattern": "[domain-name:value = 'evil.example.com']",
            "description": "malware domain",
            "labels": ["malicious-activity"],
        },
        {
            "type": "indicator",
            "id": "indicator--44444444-4444-4444-4444-444444444444",
            "pattern": "[url:value = 'http://bad.example.net/x' OR ipv4-addr:value = '198.51.100.9']",
            "description": "payload URL",
            "labels": ["malicious-activity"],
        },
        {
            "type": "indicator",
            "id": "indicator--55555555-5555-5555-5555-555555555555",
            "pattern": "[ipv4-addr:value IN ('1.1.1.1', '2.2.2.2')]",
            "description": "IN pattern",
        },
        {
            "type": "ipv4-addr",
            "id": "ipv4-addr--66666666-6666-6666-6666-666666666666",
            "value": "192.0.2.55",
            "labels": ["malicious-activity"],
        },
        {
            "type": "malware",
            "id": "malware--77777777-7777-7777-7777-777777777777",
            "name": "EvilGroup trojan",
        },
    ],
}


def test_extract_pattern_values_eq():
    assert extract_pattern_values("[ipv4-addr:value = '1.2.3.4']") == [("ipv4-addr", "1.2.3.4")]
    assert extract_pattern_values("[domain-name:value = 'evil.com']") == [("domain-name", "evil.com")]


def test_extract_pattern_values_in():
    pairs = extract_pattern_values("[ipv4-addr:value IN ('1.1.1.1', '2.2.2.2')]")
    assert pairs == [("ipv4-addr", "1.1.1.1"), ("ipv4-addr", "2.2.2.2")]


def test_parse_bundle_count():
    iocs = parse_bundle(json.dumps(BUNDLE))
    # indicator 1 (ip), indicator 2 (domain), indicator 3 (first pair → url),
    # indicator 4 (IN → two but only first emitted as value, second as tag),
    # observable ipv4-addr → 5 records total
    assert len(iocs) == 5


def test_parse_bundle_fields():
    iocs = parse_bundle(json.dumps(BUNDLE))
    first = iocs[0]
    assert first["type"] == "ip"
    assert first["value"] == "203.0.113.66"
    assert first["description"] == "C2 server used by EvilGroup"
    assert first["tags"] == ["malicious-activity", "c2"]
    assert first["reference"] == "https://example.com/report/1"
    assert first["first_seen"] == "2026-08-01T00:00:00.000Z"
    assert first["last_seen"] == "2026-08-10T00:00:00.000Z"


def test_parse_bundle_or_pattern_takes_first_kind():
    iocs = parse_bundle(json.dumps(BUNDLE))
    url_ioc = next(i for i in iocs if i["value"] == "http://bad.example.net/x")
    assert url_ioc["type"] == "url"
    # the OR partner becomes a tag
    assert "198.51.100.9" in (url_ioc["tags"] or [])


def test_parse_bundle_in_pattern_extra_as_tag():
    iocs = parse_bundle(json.dumps(BUNDLE))
    in_ioc = next(i for i in iocs if i["value"] == "1.1.1.1")
    assert in_ioc["type"] == "ip"
    assert "2.2.2.2" in (in_ioc["tags"] or [])


def test_parse_bundle_bare_observable():
    iocs = parse_bundle(json.dumps(BUNDLE))
    obs = next(i for i in iocs if i["value"] == "192.0.2.55")
    assert obs["type"] == "ip"
    assert obs["tags"] == ["malicious-activity"]


def test_parse_bundle_ignores_other_types():
    iocs = parse_bundle(json.dumps(BUNDLE))
    assert all(i["value"] not in ("EvilGroup trojan",) for i in iocs)


def test_parse_bundle_list_form():
    iocs = parse_bundle(json.dumps(BUNDLE["objects"][:1]))
    assert len(iocs) == 1
    assert iocs[0]["value"] == "203.0.113.66"
