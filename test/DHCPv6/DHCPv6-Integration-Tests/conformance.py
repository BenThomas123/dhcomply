"""Captured DHCPv6 datagrams and the host observations from one integration run."""

from dataclasses import dataclass
from ipaddress import IPv6Address
from math import isfinite
import struct


class Inconclusive(Exception):
    """The capture cannot establish a prerequisite or outcome."""


class NotApplicable(Exception):
    """The recorded DUT configuration does not support this optional feature."""


NAMES = {
    1: "solicit", 2: "advertise", 3: "request", 4: "confirm", 5: "renew",
    6: "rebind", 7: "reply", 8: "release", 9: "decline", 10: "reconfigure",
    11: "information_request", 12: "relay_forward", 13: "relay_reply",
}


def tlvs(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError(f"partial option header at byte {offset}")
        code, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + length > len(data):
            raise ValueError(f"option {code} extends past enclosing payload")
        yield code, data[offset:offset + length]
        offset += length


@dataclass(frozen=True)
class Packet:
    index: int
    time: float
    iface: str
    direction: str
    src: str
    dst: str
    sport: int
    dport: int
    raw: bytes

    @property
    def payload(self):
        return self.raw

    @property
    def name(self):
        return NAMES.get(self.raw[0], "unknown") if self.raw else "truncated"

    @property
    def xid(self):
        if len(self.raw) < 4 or self.name in ("relay_forward", "relay_reply"):
            raise ValueError("packet has no complete client/server transaction ID")
        return int.from_bytes(self.raw[1:4], "big")

    def options(self, code):
        start = 34 if self.name in ("relay_forward", "relay_reply") else 4
        if len(self.raw) < start:
            raise ValueError("truncated DHCPv6 message header")
        return [value for kind, value in tlvs(self.raw[start:]) if kind == code]


class Trace:
    def __init__(self, data):
        self.before = data["before"]
        self.after = data["after"]
        if not isinstance(self.before, dict) or not isinstance(self.after, dict):
            raise ValueError("before and after must be objects")
        self.packets = []
        for index, row in enumerate(data["packets"]):
            p = Packet(index, float(row["time"]), row["iface"], row["direction"],
                       str(IPv6Address(row["src"])), str(IPv6Address(row["dst"])),
                       row["sport"], row["dport"], bytes.fromhex(row["payload"]))
            if p.direction not in ("client", "server") or not p.iface:
                raise ValueError(f"invalid direction or interface in packet {index}")
            if not isfinite(p.time) or (index and p.time < self.packets[-1].time):
                raise ValueError(f"invalid capture time in packet {index}")
            if not all(type(port) is int and 0 <= port <= 65535 for port in (p.sport, p.dport)):
                raise ValueError(f"invalid UDP port in packet {index}")
            self.packets.append(p)

    def _messages(self, direction, name):
        found = [p for p in self.packets if p.direction == direction and p.name == name]
        assert found, f"no {direction} {name} datagram observed"
        return found

    def client(self, name):
        return self._messages("client", name)

    def server(self, name):
        return self._messages("server", name)
