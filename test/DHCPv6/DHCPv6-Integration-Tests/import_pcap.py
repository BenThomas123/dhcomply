"""Import a full-snap-length Ethernet PCAP with observations from the same lab run."""
import argparse
from ipaddress import IPv6Address
import json
from pathlib import Path
import struct


def datagram(frame):
    kind, = struct.unpack_from("!H", frame, 12)
    offset = 14
    while kind in (0x8100, 0x88a8):
        kind, = struct.unpack_from("!H", frame, offset + 2)
        offset += 4
    if kind != 0x86dd:
        return None
    ip = frame[offset:]
    if len(ip) < 40 or ip[0] >> 4 != 6:
        raise ValueError("incomplete IPv6 header")
    end = 40 + int.from_bytes(ip[4:6], "big")
    if end > len(ip):
        raise ValueError("incomplete IPv6 datagram")
    proto, pos = ip[6], 40
    while proto in (0, 43, 60):
        proto, length = struct.unpack_from("BB", ip, pos)
        pos += (length + 1) * 8
        if pos > end:
            raise ValueError("incomplete extension header")
    if proto == 44:
        raise ValueError("use reassembled UDP evidence for fragmented traffic")
    if proto != 17:
        return None
    sport, dport, length, checksum = struct.unpack_from("!HHHH", ip, pos)
    if not {546, 547}.intersection((sport, dport)):
        return None
    if length < 8 or pos + length != end:
        raise ValueError("inconsistent UDP datagram length")
    return dict(src=str(IPv6Address(ip[8:24])), dst=str(IPv6Address(ip[24:40])),
                sport=sport, dport=dport, checksum=checksum, payload=ip[pos+8:end].hex())


def capture(path, iface, mac):
    magic = {"d4c3b2a1": ("<", 10**6), "a1b2c3d4": (">", 10**6),
             "4d3cb2a1": ("<", 10**9), "a1b23c4d": (">", 10**9)}
    with path.open("rb") as stream:
        signature = stream.read(4).hex()
        if signature not in magic:
            raise ValueError("expected a classic PCAP file")
        endian, scale = magic[signature]
        major, minor, _, _, _, link = struct.unpack(endian + "HHIIII", stream.read(20))
        if (major, minor, link & 0xffff) != (2, 4, 1):
            raise ValueError("expected Ethernet PCAP version 2.4")
        while header := stream.read(16):
            sec, frac, size, original = struct.unpack(endian + "IIII", header)
            if size != original or size > 16 * 1024 * 1024:
                raise ValueError("truncated or oversized frame; capture at full snap length")
            frame = stream.read(size)
            if len(frame) != size:
                raise ValueError("truncated PCAP")
            row = datagram(frame)
            if row is not None:
                row.update(time=sec + frac / scale, iface=iface,
                           direction="client" if frame[6:12] == mac else "server")
                yield row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--link", action="append", nargs=3, required=True,
                        metavar=("INTERFACE", "DUT_MAC", "PCAP"))
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.observations.read_text(encoding="utf-8"))
    case, variant = data["case"], data["message"]
    module = Path(__file__).resolve().parent / case / f"test_{variant}.py"
    if (Path(case).name != case or Path(variant).name != variant or not module.is_file()
            or not all(isinstance(data[k], dict) for k in ("before", "after"))):
        parser.error("invalid case, message or snapshots")
    rows = []
    for iface, mac, path in args.link:
        address = bytes.fromhex(mac.replace(":", ""))
        if len(address) != 6:
            parser.error("expected six octets in the DUT MAC")
        rows.extend(capture(Path(path), iface, address))
    if not rows:
        parser.error("no DHCPv6 packets in capture")
    data["packets"] = sorted(rows, key=lambda p: p["time"])
    data["captures"] = [path for _, _, path in args.link]
    dest = args.evidence / case / (variant + ".json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(dest)


if __name__ == "__main__":
    main()
