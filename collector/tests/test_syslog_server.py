"""Integration-lite test: UDP server loop with a fake store."""

import socket
import threading
import time

from syslog_server import SyslogServer

FW_DROP = (
    "<134>Aug 26 06:00:01 UDM kernel: [496530.123456] [FW-DROP] "
    "IN=eth2 OUT= SRC=192.168.1.42 DST=224.0.0.251 LEN=143 TOS=0x00 "
    "PROTO=UDP SPT=5353 DPT=5353"
)
DHCP = "<30>Aug 26 06:00:10 UDM dnsmasq-dhcp[1234]: DHCPACK(br0) 10.0.0.50 aa:bb:cc:dd:ee:ff iPhone"


class FakeStore:
    def __init__(self):
        self.events = []
        self.inserted = []

    def insert_event(self, ev):
        self.inserted.append(ev)
        self.events.append(ev)


def _send(port: int, payload: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(payload.encode(), ("127.0.0.1", port))
    s.close()


def test_server_receives_parses_stores():
    store = FakeStore()
    server = SyslogServer(0, store)  # port 0 → OS-assigned
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    deadline = time.time() + 5
    while (server._sock is None) and time.time() < deadline:
        time.sleep(0.02)
    assert server._sock is not None
    port = server._sock.getsockname()[1]

    _send(port, FW_DROP)
    _send(port, DHCP)
    _send(port, "complete garbage \x00 line")  # should be counted, still stored

    deadline = time.time() + 5
    while len(store.inserted) < 3 and time.time() < deadline:
        time.sleep(0.05)

    server.stop()
    t.join(timeout=2)

    assert len(store.inserted) == 3
    assert server.stats["received"] == 3
    assert server.stats["parsed"] == 3
    assert server.stats["stored"] == 3
    assert server.stats["errors"] == 0

    fw = store.inserted[0]
    assert fw["action"] == "FW-DROP"
    assert fw["src_ip"] == "192.168.1.42"
    assert fw["dst_ip"] == "224.0.0.251"

    dhcp = store.inserted[1]
    assert dhcp["tag"] == "dnsmasq-dhcp"
    assert "DHCPACK" in dhcp["msg"]

    garbage = store.inserted[2]
    assert "garbage" in garbage["msg"]


def test_server_binds_specific_port():
    store = FakeStore()
    server = SyslogServer(45555, store)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    _send(45555, FW_DROP)
    deadline = time.time() + 5
    while not store.inserted and time.time() < deadline:
        time.sleep(0.05)
    server.stop()
    t.join(timeout=2)
    assert len(store.inserted) == 1
