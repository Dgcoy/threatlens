"""Parse UniFi UDM syslog lines (RFC3164) into structured event dicts.

Handles the formats UDM Pro emits to remote syslog:
  <PRI>MMM DD HH:MM:SS HOST kernel: [<epoch>] [FW-DROP] IN=.. OUT=.. SRC=.. DST=..
  plus dnsmasq / hostapd / pppd / other daemon lines (parsed generically).

SRC=/DST= fields are validated as IPs; non-IP values are kept only in `msg`.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# RFC3164 header:  optional <PRI>, "MMM DD HH:MM:SS HOST ", then the rest.
HEADER_RE = re.compile(
    r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$"
)

# daemon tag:  "kernel[1234]: msg"  or  "kernel: msg"
# (broadened for real UDM lines where the tag is a device-id like
#  "aabbccddeeff,UAP-AC-Pro-Gen2-6.8.2")
TAG_RE = re.compile(r"^([^:\s]+):\s?(.*)$")

# recover the real daemon when the syslog tag is a device-id and the
# message carries "kernel: ..." / "dnsmasq: ..." etc.
DAEMON_PREFIX_RE = re.compile(
    r"^(kernel|dnsmasq-dhcp|dnsmasq|hostapd|pppd|ubios|unifi|network|syslog)(?:\[\d+\])?:"
)

# iptables/xtables style key=value fields.
# Values never contain '=' and never swallow a following KEY= pair
# (handles both "OUT= SRC=…" and "OUT= MAC=01:00:…" → OUT is empty → skipped).
FIELD_RE = re.compile(r"\b(SRC|DST|SPT|DPT|PROTO|IN|OUT)\s*=\s*([^\s=]+)(?=\s+\w+=|\s*$)")

# UniFi log prefix inside kernel messages, e.g. [FW-DROP] [FW-ACCEPT] [DPIA-BLOCK].
# Must start with a letter so kernel timestamps like [496530.123456] are skipped.
PREFIX_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9_.-]*)\]")

# dnsmasq DNS query:  "query[A] example.com from 10.0.0.50"
DNS_QUERY_RE = re.compile(r"query\[(?:[A-Za-z0-9]+)\]\s+([^\s]+)\s+from\s+([^\s]+)")
# dnsmasq DHCPACK:    "DHCPACK(br0) 10.0.0.50 aa:bb:cc:dd:ee:ff iPhone"
DHCP_HOST_RE = re.compile(r"DHCPACK\(\w+\)\s+\S+\s+\S+\s+(\S+)")

FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron", 16: "local0",
    17: "local1", 18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}
SEVERITIES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning",
    5: "notice", 6: "info", 7: "debug",
}


def _parse_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _coerce_year(naive: datetime, now: datetime) -> datetime:
    """Attach a year to a naive RFC3164 timestamp, handling Dec/Jan rollover."""
    now_naive = now.astimezone(timezone.utc).replace(tzinfo=None)
    naive = naive.replace(year=now_naive.year)
    if naive > now_naive + timedelta(days=1):
        naive = naive.replace(year=now_naive.year - 1)
    elif naive < now_naive - timedelta(days=365):
        naive = naive.replace(year=now_naive.year + 1)
    return naive


def parse_syslog_line(line: str, *, now: datetime | None = None,
                      tz: str = "UTC") -> dict | None:
    """Parse one syslog line into a normalized event dict (or None if garbage).

    `now` overrides the clock (tests); `tz` is the UDM's local timezone name
    (e.g. "America/Chicago"); timestamps are converted to UTC.
    """
    now = now or datetime.now(timezone.utc)
    raw = line.rstrip("\r\n")
    if not raw:
        return None

    m = HEADER_RE.match(raw)
    if m:
        pri, mon, day, hh, mm, ss, host, rest = m.groups()
        day = int(day)
        try:
            naive = datetime(2000, MONTHS[mon], day, int(hh), int(mm), int(ss))
        except ValueError:
            return None
        naive = _coerce_year(naive, now)
        try:
            ts = naive.replace(tzinfo=ZoneInfo(tz)).astimezone(timezone.utc)
        except ZoneInfoNotFoundError:
            ts = naive.replace(tzinfo=timezone.utc)
        pri = int(pri) if pri else None
    else:
        # no RFC3164 header (bare kernel line) — still try to extract fields
        pri = None
        host = None
        ts = now
        rest = raw

    # UDM Pro doubles the hostname: "Aug 26 06:37:11 UDMPro UDMPro [rule] ..."
    if host and rest.startswith(host + " "):
        rest = rest[len(host) + 1:]

    tm = TAG_RE.match(rest)
    if tm:
        tag, msg = tm.groups()
        tag = re.sub(r"\[\d+\]$", "", tag)     # drop [pid] suffix
        # device-id tag (contains , or spaces) with "kernel: ..." in message
        if ("," in tag or " " in tag or "+" in tag):
            m = DAEMON_PREFIX_RE.match(msg)
            if m:
                tag = m.group(1)
                msg = msg[m.end():].lstrip()
    else:
        tag, msg = None, rest

    fields = {k: v for k, v in FIELD_RE.findall(msg)}
    # Firewall log prefixes ([FW-DROP] etc.) appear in kernel messages and in
    # headerless lines that still carry iptables fields; other daemons use [X]
    # for unrelated things (dnsmasq record types).
    has_iptables_fields = any(k in fields for k in ("SRC", "DST", "IN", "OUT"))
    if (tag == "kernel" or (tag is None and has_iptables_fields)) and has_iptables_fields:
        prefix = PREFIX_RE.search(msg)
        action = prefix.group(1) if prefix else None
    else:
        action = None

    # hostname context from dnsmasq (DNS queries + DHCPACK client names)
    hostname = None
    if tag == "dnsmasq":
        m = DNS_QUERY_RE.search(msg)
        if m:
            hostname = m.group(1)
            client_ip = _parse_ip(m.group(2))
            if client_ip:
                fields.setdefault("SRC", client_ip)   # querier = source
    elif tag == "dnsmasq-dhcp":
        m = DHCP_HOST_RE.search(msg)
        if m:
            hostname = m.group(1)

    ev = {
        "ts": ts,
        "host": host,
        "pri": pri,
        "facility": FACILITIES.get(pri // 8) if pri is not None else None,
        "severity": SEVERITIES.get(pri % 8) if pri is not None else None,
        "tag": tag,
        "action": action,
        "src_ip": _parse_ip(fields["SRC"]) if "SRC" in fields else None,
        "dst_ip": _parse_ip(fields["DST"]) if "DST" in fields else None,
        "src_port": int(fields["SPT"]) if fields.get("SPT", "").isdigit() else None,
        "dst_port": int(fields["DPT"]) if fields.get("DPT", "").isdigit() else None,
        "proto": fields.get("PROTO"),
        "in_if": fields.get("IN"),
        "out_if": fields.get("OUT"),
        "hostname": hostname,
        "msg": msg,
        "raw": raw,
    }
    return ev
