"""In-memory IOC matcher unit tests."""

from matcher import IocMatcher

# rows as returned by PostgresStore.load_iocs()
ROWS = [
    {"id": 1, "type": "ip", "value": "203.0.113.66", "feed_id": 10, "feed_name": "TestFeed"},
    {"id": 2, "type": "cidr", "value": "198.51.100.0/24", "feed_id": 10, "feed_name": "TestFeed"},
    {"id": 3, "type": "domain", "value": "evil.example.com", "feed_id": 11, "feed_name": "DomFeed"},
    {"id": 4, "type": "url", "value": "http://bad.example.net/x", "feed_id": 11, "feed_name": "DomFeed"},
    {"id": 5, "type": "ip", "value": "10.0.0.174", "feed_id": 12, "feed_name": "LocalFeed"},
]


def _matcher():
    m = IocMatcher()
    m.load_rows(ROWS)
    return m


def test_exact_ip_src_and_dst():
    m = _matcher()
    hits = m.match_event({"src_ip": "203.0.113.66", "dst_ip": "1.1.1.1", "hostname": None})
    assert len(hits) == 1
    assert hits[0]["match_type"] == "src"
    assert hits[0]["matched_value"] == "203.0.113.66"
    assert hits[0]["feed_name"] == "TestFeed"

    hits = m.match_event({"src_ip": "1.1.1.1", "dst_ip": "203.0.113.66", "hostname": None})
    assert len(hits) == 1
    assert hits[0]["match_type"] == "dst"


def test_cidr_containment():
    m = _matcher()
    inside = m.match_event({"src_ip": "198.51.100.42", "dst_ip": "1.1.1.1", "hostname": None})
    assert len(inside) == 1
    assert inside[0]["match_type"] == "src"
    outside = m.match_event({"src_ip": "198.51.101.42", "dst_ip": "1.1.1.1", "hostname": None})
    assert outside == []


def test_ip_matches_cidr_and_exact_both():
    m = _matcher()
    # 10.0.0.174 exists as exact; also craft an event hitting a cidr + exact
    m.load_rows(ROWS + [{"id": 6, "type": "cidr", "value": "10.0.0.0/24",
                         "feed_id": 13, "feed_name": "CidrFeed"}])
    hits = m.match_event({"src_ip": "10.0.0.174", "dst_ip": None, "hostname": None})
    kinds = {(h["match_type"], h["feed_name"]) for h in hits}
    assert ("src", "LocalFeed") in kinds
    assert ("src", "CidrFeed") in kinds


def test_domain_exact_and_subdomain():
    m = _matcher()
    exact = m.match_event({"src_ip": None, "dst_ip": None, "hostname": "evil.example.com"})
    assert len(exact) == 1
    assert exact[0]["feed_name"] == "DomFeed"
    sub = m.match_event({"src_ip": None, "dst_ip": None, "hostname": "sub.evil.example.com"})
    assert len(sub) == 1
    assert sub[0]["matched_value"] == "sub.evil.example.com"
    near = m.match_event({"src_ip": None, "dst_ip": None, "hostname": "notevil.example.com"})
    assert near == []          # suffix boundary respected


def test_url_ioc_matches_hostname():
    m = _matcher()
    hits = m.match_event({"src_ip": None, "dst_ip": None, "hostname": "bad.example.net"})
    assert len(hits) == 1
    assert hits[0]["feed_name"] == "DomFeed"
    # port on hostname still matches
    hits2 = m.match_event({"src_ip": None, "dst_ip": None, "hostname": "bad.example.net:8080"})
    assert len(hits2) == 1


def test_no_match():
    m = _matcher()
    assert m.match_event({"src_ip": "9.9.9.9", "dst_ip": "8.8.8.8", "hostname": "ok.com"}) == []


def test_blank_event():
    m = _matcher()
    assert m.match_event({}) == []


def test_bad_cidr_row_skipped():
    m = _matcher()
    n = m.load_rows([{"id": 99, "type": "cidr", "value": "not-a-cidr",
                      "feed_id": 1, "feed_name": "x"}])
    assert n == 0
    assert m.match_event({"src_ip": "1.2.3.4", "dst_ip": None, "hostname": None}) == []
