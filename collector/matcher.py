"""In-memory IOC matcher: events → detections.

Loads active IOCs (with feed attribution) into fast lookup structures:
  - exact IPs        → set
  - CIDRs            → linear containment scan (Spamhaus-scale is ~2k nets)
  - domains / URLs   → exact + suffix lookup on hostnames
"""

from __future__ import annotations

import ipaddress

# hostname of a URL IOC (http://evil.example/x → evil.example)
from shared.ioc_utils import url_hostname


class IocRef:
    __slots__ = ("ioc_id", "feed_id", "feed_name", "type", "value")

    def __init__(self, ioc_id, feed_id, feed_name, ioc_type, value):
        self.ioc_id = ioc_id
        self.feed_id = feed_id
        self.feed_name = feed_name
        self.type = ioc_type
        self.value = value


class IocMatcher:
    def __init__(self):
        self.ip_exact: dict[str, list[IocRef]] = {}
        self.cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IocRef]] = []
        self.domains: dict[str, list[IocRef]] = {}
        self.ref_count = 0

    def clear(self) -> None:
        self.ip_exact.clear()
        self.cidrs.clear()
        self.domains.clear()
        self.ref_count = 0

    def load_rows(self, rows: list[dict]) -> int:
        """rows: [{id, type, value, feed_id, feed_name}]. Returns refs loaded."""
        self.clear()
        for row in rows:
            ref = IocRef(
                row["id"], row["feed_id"], row["feed_name"],
                row["type"], row["value"],
            )
            if row["type"] == "ip":
                self.ip_exact.setdefault(row["value"], []).append(ref)
                self.ref_count += 1
            elif row["type"] == "cidr":
                try:
                    net = ipaddress.ip_network(row["value"], strict=False)
                except ValueError:
                    continue
                self.cidrs.append((net, ref))
                self.ref_count += 1
            elif row["type"] == "domain":
                self.domains.setdefault(row["value"].lower(), []).append(ref)
                self.ref_count += 1
            elif row["type"] == "url":
                host = url_hostname(row["value"])
                if host:
                    host = host.lower().rstrip(".")
                    self.domains.setdefault(host, []).append(ref)
                    self.ref_count += 1
        return self.ref_count

    def _match_ip(self, ip_str: str, match_type: str, detections: list[dict]) -> None:
        refs = self.ip_exact.get(ip_str)
        if refs:
            for r in refs:
                detections.append(self._det(r, match_type, ip_str))
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return
        for net, r in self.cidrs:
            if addr in net:
                detections.append(self._det(r, match_type, ip_str))

    def _match_hostname(self, hostname: str, match_type: str, detections: list[dict]) -> None:
        h = hostname.lower().rstrip(".")
        if ":" in h:                       # strip any :port suffix
            h = h.split(":", 1)[0]
        labels = h.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            refs = self.domains.get(suffix)
            if refs:
                for r in refs:
                    detections.append(self._det(r, match_type, h))

    @staticmethod
    def _det(ref: IocRef, match_type: str, matched_value: str) -> dict:
        return {
            "ioc_id": ref.ioc_id,
            "feed_id": ref.feed_id,
            "feed_name": ref.feed_name,
            "match_type": match_type,
            "matched_value": matched_value,
        }

    def match_event(self, ev: dict) -> list[dict]:
        """Return detection dicts for an event (may be empty)."""
        detections: list[dict] = []
        if ev.get("src_ip"):
            self._match_ip(ev["src_ip"], "src", detections)
        if ev.get("dst_ip"):
            self._match_ip(ev["dst_ip"], "dst", detections)
        if ev.get("hostname"):
            self._match_hostname(ev["hostname"], "host", detections)
        return detections
