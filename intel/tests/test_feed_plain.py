"""Plain + CSV feed parsing."""

from feed_plain import parse_csv, parse_plain


def test_plain_ips_and_comments():
    text = """
# Spamhaus DROP list
; version 2.0
1.2.3.0/24 ; SBL12345 comment
5.6.7.8
10.11.12.13/16

bad-line-not-an-ioc
evil.example.com
http://evil.example.com/path
"""
    iocs = parse_plain(text)
    kinds = {i["value"]: i["type"] for i in iocs}
    assert kinds == {
        "1.2.3.0/24": "cidr",
        "5.6.7.8": "ip",
        "10.11.12.13/16": "cidr",
        "evil.example.com": "domain",
        "http://evil.example.com/path": "url",
    }


def test_plain_trailing_comment_stripped():
    iocs = parse_plain("1.2.3.0/24 ; SBL12345\n")
    assert iocs[0]["value"] == "1.2.3.0/24"
    assert iocs[0]["reference"] is None  # comment not kept


def test_plain_blank_only_is_empty():
    assert parse_plain("") == []
    assert parse_plain("\n\n# nothing\n") == []


def test_csv_basic_with_header():
    text = (
        "id,ioc,threat_type,malware\n"
        "1,1.2.3.4,botnet_cc,evil_family\n"
        "2,5.6.7.8,payload,other\n"
    )
    cfg = {"has_header": True, "value_column": 2, "description_column": 4}
    iocs = parse_csv(text, cfg)
    assert len(iocs) == 2
    assert iocs[0]["value"] == "1.2.3.4"
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["description"] == "evil_family"


def test_csv_quoted_and_tags_column():
    text = (
        'id,ioc,malware,tags\n'
        '1,"http://evil.example.com/a","malware-x","c2, botnet"\n'
        '2,"5.6.7.8","",""\n'
    )
    cfg = {"has_header": True, "value_column": 2, "description_column": 3,
           "tags_column": 4}
    iocs = parse_csv(text, cfg)
    assert iocs[0]["type"] == "url"
    assert iocs[0]["value"] == "http://evil.example.com/a"
    assert iocs[0]["tags"] == ["c2", "botnet"]
    assert iocs[1]["type"] == "ip"
    assert iocs[1]["tags"] is None


def test_csv_no_header():
    text = "1.2.3.4,some description\n5.6.7.8,another\n"
    cfg = {"has_header": False, "value_column": 1, "description_column": 2}
    iocs = parse_csv(text, cfg)
    assert len(iocs) == 2
    assert iocs[1]["description"] == "another"


def test_csv_skips_junk_rows():
    text = "id,value\n1,not-an-ioc\n2,9.9.9.9\n"
    cfg = {"has_header": True, "value_column": 2}
    iocs = parse_csv(text, cfg)
    assert len(iocs) == 1
    assert iocs[0]["value"] == "9.9.9.9"


def test_csv_abusech_comment_header_block():
    # abuse.ch exports lead with '#' comment rows (header lives in comments,
    # no real header row); values are quoted with a leading space
    text = (
        "################################################################\n"
        "# ThreatFox IOCs: recent additions - CSV format                #\n"
        '# "first_seen_utc", ioc_id, ioc_value, type, threat_type, malware\n'
        '2026-08-26 11:20:55, "1888146", "http://evil.example.com/x", "url", "botnet_cc", "win.remus"\n'
        '2026-08-26 11:19:01, "1888145", "p25so1h6.evil.net", "domain", "payload_delivery", "js.clearfake"\n'
        '2026-08-26 11:18:00, "1888144", "bad value", "x", "y", "z"\n'
    )
    cfg = {"has_header": False, "value_column": 3, "description_column": 6,
           "tags_column": 5}
    iocs = parse_csv(text, cfg)
    assert len(iocs) == 2
    assert iocs[0]["value"] == "http://evil.example.com/x"
    assert iocs[0]["type"] == "url"
    assert iocs[0]["description"] == "win.remus"
    assert iocs[0]["tags"] == ["botnet_cc"]
    assert iocs[1]["value"] == "p25so1h6.evil.net"
    assert iocs[1]["description"] == "js.clearfake"
