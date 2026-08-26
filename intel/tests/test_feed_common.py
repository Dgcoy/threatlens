"""Type inference + value cleaning."""

from feed_common import clean_value, infer_type, url_hostname


def test_infer_ip():
    assert infer_type("1.2.3.4") == "ip"
    assert infer_type("8.8.8.8") == "ip"
    assert infer_type("2001:db8::1") == "ip"  # IPv6


def test_infer_cidr():
    assert infer_type("1.2.3.0/24") == "cidr"
    assert infer_type("10.0.0.0/8") == "cidr"


def test_infer_domain():
    assert infer_type("evil.example.com") == "domain"
    assert infer_type("bad-domain.net") == "domain"
    assert infer_type("*.example.com") == "domain"


def test_infer_url():
    assert infer_type("http://evil.example.com/path") == "url"
    assert infer_type("https://evil.example.com/path?q=1") == "url"


def test_infer_junk():
    assert infer_type("") is None
    assert infer_type("not an indicator") is None
    assert infer_type("1.2.3.999") is None
    assert infer_type("999.1.1.1") is None


def test_clean_value_strips_quotes():
    assert clean_value('"1.2.3.4"') == "1.2.3.4"
    assert clean_value("'evil.com'") == "evil.com"
    assert clean_value(" 1.2.3.4 ") == "1.2.3.4"


def test_url_hostname():
    assert url_hostname("https://evil.example.com/x?y=1") == "evil.example.com"
    assert url_hostname("http://a.b.c:8080/z") == "a.b.c:8080"
