"""Unit tests for the UniFi UDM syslog parser."""

from datetime import datetime, timezone

from unifi_parser import parse_syslog_line

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)

FW_DROP = (
    "<134>Aug 26 06:00:01 UDM kernel: [496530.123456] [FW-DROP] "
    "IN=eth2 OUT= MAC=01:00:5e:00:00:fb:9c:b6:54:ab:cd:ef:08:00 "
    "SRC=192.168.1.42 DST=224.0.0.251 LEN=143 TOS=0x00 PREC=0x00 TTL=1 "
    "ID=58355 PROTO=UDP SPT=5353 DPT=5353 LEN=123"
)

FW_ACCEPT = (
    "Aug 26 06:00:05 UDM kernel: [496531.654321] [FW-ACCEPT] IN=br0 OUT=eth1 "
    "SRC=10.0.0.174 DST=1.1.1.1 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=1234 DF "
    "PROTO=TCP SPT=54321 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0"
)

DHCP = "<30>Aug 26 06:00:10 UDM dnsmasq-dhcp[1234]: DHCPACK(br0) 10.0.0.50 aa:bb:cc:dd:ee:ff iPhone"

DNS_QUERY = "<30>Aug 26 06:00:11 UDM dnsmasq[1234]: query[A] example.com from 10.0.0.50"

HOSTAPD = "<30>Aug 26 06:01:00 UDM hostapd[5678]: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated"

DPIA = (
    "<134>Aug 26 06:02:00 UDM kernel: [496600.111111] [DPIA-BLOCK] "
    "IN=eth1 OUT=eth2 SRC=8.8.8.8 DST=10.10.10.10 LEN=60 TOS=0x00 "
    "PROTO=TCP SPT=443 DPT=5514"
)

BARE = "[FW-DROP] IN=eth2 OUT= SRC=192.168.1.42 DST=8.8.8.8 LEN=84 PROTO=ICMP TYPE=8 CODE=0"

PPPD = "<86>Aug 26 06:04:00 UDM pppd[2345]: secondary DNS address 8.8.4.4"

# REAL UDM Pro captures (anonymized — format preserved):
REAL_DMZ = (
    '<13>Aug 26 06:37:11 UDMPro UDMPro [DMZ_WAN-A-10000] '
    'DESCR="DMZ - Egress Traffic" IN=br99 OUT=eth8 '
    "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb SRC=192.168.99.3 DST=8.8.8.8 "
    "LEN=80 TOS=00 PREC=0x00 TTL=63 ID=62292 DF PROTO=UDP SPT=55206 DPT=53 "
    "LEN=60 MARK=760000 "
)
REAL_KERN_LINK = (
    "<6>Aug 26 07:11:08 UDMPro UDMPro kernel: eth [al_mod_eth_2]: "
    "set link speed to 1000Mbps"
)
REAL_AP = (
    "<4>Aug 26 07:11:07 OfficeAP aabbccddeeff,UAP-AC-Pro-Gen2-6.8.2: "
    "kernel: [254678.123456] [UAP-FW] IN=br0 OUT=wlan0 SRC=192.168.9.10 DST=1.2.3.4 "
    "PROTO=TCP SPT=12345 DPT=80"
)


def test_firewall_drop_full():
    ev = parse_syslog_line(FW_DROP, now=NOW)
    assert ev is not None
    assert ev["ts"] == datetime(2026, 8, 26, 6, 0, 1, tzinfo=timezone.utc)
    assert ev["host"] == "UDM"
    assert ev["tag"] == "kernel"
    assert ev["action"] == "FW-DROP"
    assert ev["src_ip"] == "192.168.1.42"
    assert ev["dst_ip"] == "224.0.0.251"
    assert ev["src_port"] == 5353
    assert ev["dst_port"] == 5353
    assert ev["proto"] == "UDP"
    assert ev["in_if"] == "eth2"
    assert ev["out_if"] is None
    assert ev["facility"] == "local0"      # 134 // 8 = 16
    assert ev["severity"] == "info"        # 134 % 8 = 6


def test_firewall_accept_no_pri():
    ev = parse_syslog_line(FW_ACCEPT, now=NOW)
    assert ev is not None
    assert ev["pri"] is None
    assert ev["action"] == "FW-ACCEPT"
    assert ev["src_ip"] == "10.0.0.174"
    assert ev["dst_ip"] == "1.1.1.1"
    assert ev["src_port"] == 54321
    assert ev["dst_port"] == 443
    assert ev["proto"] == "TCP"
    assert ev["out_if"] == "eth1"


def test_dhcp_line():
    ev = parse_syslog_line(DHCP, now=NOW)
    assert ev is not None
    assert ev["tag"] == "dnsmasq-dhcp"
    assert ev["action"] is None
    assert ev["src_ip"] is None
    assert ev["hostname"] == "iPhone"  # DHCPACK client name
    assert "DHCPACK" in ev["msg"]
    assert ev["facility"] == "daemon"      # 30 // 8 = 3
    assert ev["severity"] == "info"        # 30 % 8 = 6


def test_dns_query_line():
    ev = parse_syslog_line(DNS_QUERY, now=NOW)
    assert ev is not None
    assert ev["tag"] == "dnsmasq"
    assert ev["action"] is None  # [A] is a record type, not a firewall prefix
    assert "example.com" in ev["msg"]
    assert ev["hostname"] == "example.com"
    assert ev["src_ip"] == "10.0.0.50"  # querier becomes source
    assert ev["dst_ip"] is None


def test_hostapd_line():
    ev = parse_syslog_line(HOSTAPD, now=NOW)
    assert ev is not None
    assert ev["tag"] == "hostapd"
    assert "authenticated" in ev["msg"]


def test_dpia_block():
    ev = parse_syslog_line(DPIA, now=NOW)
    assert ev is not None
    assert ev["action"] == "DPIA-BLOCK"
    assert ev["src_ip"] == "8.8.8.8"
    assert ev["dst_ip"] == "10.10.10.10"
    assert ev["dst_port"] == 5514


def test_bare_kernel_line_no_header():
    ev = parse_syslog_line(BARE, now=NOW)
    assert ev is not None
    assert ev["host"] is None
    assert ev["action"] == "FW-DROP"
    assert ev["src_ip"] == "192.168.1.42"
    assert ev["dst_ip"] == "8.8.8.8"
    assert ev["proto"] == "ICMP"
    # no header → timestamp is "now"
    assert ev["ts"] == NOW


def test_pppd_line():
    ev = parse_syslog_line(PPPD, now=NOW)
    assert ev is not None
    assert ev["tag"] == "pppd"
    assert ev["src_ip"] is None


def test_timezone_conversion():
    # UDM in America/Chicago: 06:00 local == 11:00 UTC (CDT, UTC-5)
    ev = parse_syslog_line(FW_ACCEPT, now=NOW, tz="America/Chicago")
    assert ev["ts"].hour == 11
    assert ev["ts"].minute == 0


def test_year_rollover():
    # Dec 31 local time with "now" = Jan 1 → previous year
    line = "<134>Dec 31 23:59:59 UDM kernel: [1.0] [FW-DROP] IN=eth2 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=ICMP"
    now = datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
    ev = parse_syslog_line(line, now=now)
    assert ev is not None
    assert ev["ts"].year == 2025
    assert ev["ts"].month == 12
    assert ev["ts"].day == 31


def test_invalid_src_ip_kept_in_msg():
    line = "<134>Aug 26 06:00:01 UDM kernel: [1.0] [FW-DROP] IN=eth2 OUT= SRC=router.local DST=5.6.7.8 PROTO=ICMP"
    ev = parse_syslog_line(line, now=NOW)
    assert ev is not None
    assert ev["src_ip"] is None
    assert "SRC=router.local" in ev["msg"]


def test_empty_line_returns_none():
    assert parse_syslog_line("", now=NOW) is None
    assert parse_syslog_line("\r\n", now=NOW) is None


def test_garbage_line_still_returns_event():
    # unknown text without header still yields a minimal event (never drop data)
    ev = parse_syslog_line("something weird without any structure", now=NOW)
    assert ev is not None
    assert ev["msg"] == "something weird without any structure"


def test_real_udm_dmz_firewall_line():
    # live UDM Pro capture: doubled hostname, rule-name prefix, no tag
    ev = parse_syslog_line(REAL_DMZ, now=NOW)
    assert ev is not None
    assert ev["host"] == "UDMPro"
    assert ev["tag"] is None
    assert ev["action"] == "DMZ_WAN-A-10000"   # the iptables rule that fired
    assert ev["src_ip"] == "192.168.99.3"
    assert ev["dst_ip"] == "8.8.8.8"
    assert ev["src_port"] == 55206
    assert ev["dst_port"] == 53
    assert ev["proto"] == "UDP"
    assert ev["in_if"] == "br99"
    assert ev["out_if"] == "eth8"
    assert ev["facility"] == "user"            # 13 // 8 = 1
    assert ev["severity"] == "notice"          # 13 % 8 = 5


def test_real_udm_kernel_link_line_no_false_action():
    ev = parse_syslog_line(REAL_KERN_LINK, now=NOW)
    assert ev is not None
    assert ev["host"] == "UDMPro"
    assert ev["tag"] == "kernel"               # recovered from doubled host
    assert ev["action"] is None                # no iptables fields → no action
    assert "link speed" in ev["msg"]


def test_real_ap_line_recovers_kernel_tag():
    ev = parse_syslog_line(REAL_AP, now=NOW)
    assert ev is not None
    assert ev["host"] == "OfficeAP"
    assert ev["tag"] == "kernel"               # recovered from device-id tag
    assert ev["action"] == "UAP-FW"
    assert ev["src_ip"] == "192.168.9.10"
    assert ev["dst_ip"] == "1.2.3.4"
    assert ev["dst_port"] == 80
