#!/usr/bin/env python3
"""Send synthetic UDM syslog datagrams to a collector — validation tooling.

Usage:
    python3 scripts/inject_syslog.py --target 10.10.10.10:514 [--count N] [--rate N/sec] [--fixtures]
"""

import argparse
import random
import socket
import time

FIXTURES = [
    "<134>Aug 26 06:00:01 UDM kernel: [496530.123456] [FW-DROP] "
    "IN=eth2 OUT= MAC=01:00:5e:00:00:fb:9c:b6:54:ab:cd:ef:08:00 "
    "SRC=192.168.1.42 DST=224.0.0.251 LEN=143 TOS=0x00 PREC=0x00 TTL=1 "
    "ID=58355 PROTO=UDP SPT=5353 DPT=5353 LEN=123",
    "<134>Aug 26 06:00:05 UDM kernel: [496531.654321] [FW-ACCEPT] IN=br0 OUT=eth1 "
    "SRC=192.168.1.174 DST=1.1.1.1 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=1234 DF "
    "PROTO=TCP SPT=54321 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0",
    "<134>Aug 26 06:02:00 UDM kernel: [496600.111111] [DPIA-BLOCK] "
    "IN=eth1 OUT=eth2 SRC=8.8.8.8 DST=10.10.10.10 LEN=60 TOS=0x00 "
    "PROTO=TCP SPT=443 DPT=5514",
    "<30>Aug 26 06:00:10 UDM dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff iPhone",
    "<30>Aug 26 06:00:11 UDM dnsmasq[1234]: query[A] example.com from 192.168.1.50",
    "<30>Aug 26 06:01:00 UDM hostapd[5678]: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated",
    "<86>Aug 26 06:04:00 UDM pppd[2345]: secondary DNS address 8.8.4.4",
    # known-bad sample used by detection tests later (203.0.113.66 = TEST-NET-3)
    "<134>Aug 26 06:05:00 UDM kernel: [496700.333333] [FW-DROP] IN=eth1 OUT=eth2 "
    "SRC=203.0.113.66 DST=10.10.10.10 LEN=60 TOS=0x00 PROTO=TCP SPT=4444 DPT=8080",
]

INTERNAL = [
    "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24",
    "192.168.4.0/24", "192.168.5.0/24",
]


def random_event() -> str:
    src = random.choice(INTERNAL).replace("/24", "")[:-1] + str(random.randint(2, 250))
    if random.random() < 0.3:
        # external source → internal dest (inbound)
        src = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst = random.choice(INTERNAL).replace("/24", "")[:-1] + str(random.randint(2, 250))
        action = random.choice(["FW-DROP", "FW-ACCEPT"])
    else:
        dst = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        action = random.choice(["FW-ACCEPT", "FW-ACCEPT", "FW-DROP"])
    proto = random.choice(["TCP", "UDP", "TCP", "UDP", "ICMP"])
    if proto == "ICMP":
        tail = "LEN=84 PROTO=ICMP TYPE=8 CODE=0"
        sport, dport = "", ""
    else:
        sport = f" SPT={random.randint(1024, 65535)}"
        dport = f" DPT={random.choice([22, 53, 80, 443, 445, 3389, 8080, 5353])}"
        tail = f"LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1, 65000)} PROTO={proto}{sport}{dport}"
    return (f"<134>Aug 26 06:00:00 UDM kernel: [496800.000000] [{action}] "
            f"IN=eth1 OUT=eth2 SRC={src} DST={dst} {tail}")


def main():
    ap = argparse.ArgumentParser(description="Inject synthetic UDM syslog traffic")
    ap.add_argument("--target", default="127.0.0.1:514", help="collector host:port")
    ap.add_argument("--count", type=int, default=10, help="datagrams to send")
    ap.add_argument("--rate", type=float, default=10.0, help="datagrams per second")
    ap.add_argument("--fixtures", action="store_true", help="send the fixed fixture set first")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    host, _, port = args.target.rpartition(":")
    port = int(port)
    random.seed(args.seed)

    lines = []
    if args.fixtures:
        lines += FIXTURES
    lines += [random_event() for _ in range(args.count)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for i, line in enumerate(lines):
        sock.sendto(line.encode(), (host, port))
        sent += 1
        if args.rate > 0 and i < len(lines) - 1:
            time.sleep(1.0 / args.rate)
    print(f"sent {sent} datagrams to {host}:{port} (fixtures={args.fixtures}, count={args.count})")


if __name__ == "__main__":
    main()
