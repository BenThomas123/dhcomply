"""Exercise the compiled Linux client on a disposable container's private dummy link.

The peer receives normal DHCPv6 multicast on UDP/547. Captured addresses and
ports come from the kernel. Each invocation starts the real executable.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from conformance import NAMES, tlvs

GROUP = "ff02::1:2"
INTERFACE = "dhcptest0"
LINK = "fe80::c"
ROOT = Path(__file__).resolve().parent
MESSAGES = ("solicit", "request", "information_request")
IDS = ("DC-01-001", "DC-01-002", "DC-01-003", "DC-01-005", "DC-01-006",
       "DC-01-007", "DC-01-008", "DC-01-009")


def configure_link():
    # SIOCSIFADDR and SIOCADDRT use the Linux IPv6 socket ABI.
    import fcntl
    if not Path("/.dockerenv").exists() or set(os.listdir("/sys/class/net")) != {"lo"}:
        raise SystemExit("run live.py in a disposable Linux container with --network none")
    # Linux loops locally originated multicast back to subscribed UDP sockets
    # on a multicast-capable link. Use a dummy interface with no external peer.
    def attr(kind, value):
        length = 4 + len(value)
        return struct.pack("=HH", length, kind) + value + bytes(-length % 4)

    body = struct.pack("=BBHiII", 0, 0, 0, 0, 0, 0)
    body += attr(3, INTERFACE.encode() + b"\0")
    body += attr(18, attr(1, b"dummy\0"))
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as netlink:
        netlink.sendto(struct.pack("=IHHII", 16 + len(body), 16, 0x605, 1, 0) + body, (0, 0))
        ack = netlink.recv(4096)
        error, = struct.unpack_from("=i", ack, 16)
        if error:
            raise OSError(-error, os.strerror(-error))
    iface = socket.if_nametoindex(INTERFACE)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        ifreq = bytearray(40)
        ifreq[:len(INTERFACE)] = INTERFACE.encode()
        fcntl.ioctl(sock, 0x8913, ifreq, True)
        flags, = struct.unpack_from("H", ifreq, 16)
        struct.pack_into("H", ifreq, 16, flags | 0x1001)  # IFF_UP | IFF_MULTICAST
        fcntl.ioctl(sock, 0x8914, ifreq)
        address = struct.pack("=16sIi", socket.inet_pton(socket.AF_INET6, LINK), 64, iface)
        try:
            fcntl.ioctl(sock, 0x8916, address)
        except FileExistsError:
            pass

        class Route(ctypes.Structure):
            _fields_ = [("dest", ctypes.c_ubyte * 16), ("src", ctypes.c_ubyte * 16),
                        ("gateway", ctypes.c_ubyte * 16), ("kind", ctypes.c_uint32),
                        ("dst_len", ctypes.c_uint16), ("src_len", ctypes.c_uint16),
                        ("metric", ctypes.c_uint32), ("info", ctypes.c_ulong),
                        ("flags", ctypes.c_uint32), ("index", ctypes.c_int)]
        route = Route()
        route.dest[0] = 255
        route.dst_len, route.metric, route.flags, route.index = 8, 1, 1, iface
        try:
            fcntl.ioctl(sock, 0x890B, bytes(route))
        except FileExistsError:
            pass
    return iface


def option(code, payload):
    return struct.pack("!HH", code, len(payload)) + payload


def remove_link(iface):
    body = struct.pack("=BBHiII", 0, 0, 0, iface, 0, 0)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as netlink:
        netlink.sendto(struct.pack("=IHHII", 16 + len(body), 17, 5, 1, 0) + body, (0, 0))
        error, = struct.unpack_from("=i", netlink.recv(4096), 16)
        if error:
            raise OSError(-error, os.strerror(-error))


def offer(solicit):
    options = dict(tlvs(solicit[4:]))
    iaid = options[3][:4]
    address = socket.inet_pton(socket.AF_INET6, "2001:db8::77")
    binding = option(5, address + struct.pack("!II", 120, 180))
    return (b"\x02" + solicit[1:4] + option(1, options[1])
            + option(2, bytes.fromhex("00030001020000000077"))
            + option(3, iaid + struct.pack("!II", 60, 90) + binding)
            + option(7, b"\xff"))


def capture(binary, iface, message, count, timeout, on_last=None):
    packets, indices = [], []
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
        peer.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        peer.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack("@I", iface))
        peer.bind(("::", 547))
        mode = "S" if message == "information_request" else "N"
        process = subprocess.Popen([str(binary), mode, INTERFACE], start_new_session=True,
                                   stdout=subprocess.DEVNULL, stderr=sys.stderr)
        deadline = time.monotonic() + timeout
        try:
            while len(indices) < count:
                if process.poll() is not None:
                    raise RuntimeError(f"DUT exited early with status {process.returncode}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting for {message}")
                peer.settimeout(min(0.25, remaining))
                try:
                    raw, control, flags, sender = peer.recvmsg(65535, 128)
                except socket.timeout:
                    continue
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise RuntimeError("incomplete observation")
                info = next(value for level, kind, value in control
                            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO)
                dest, index = struct.unpack("@16sI", info)
                packets.append(dict(time=time.monotonic(), iface=socket.if_indextoname(index),
                                    direction="client", src=sender[0], sport=sender[1],
                                    dst=socket.inet_ntop(socket.AF_INET6, dest), dport=547,
                                    payload=raw.hex()))
                # The stimulus determines the expected type. Do not filter an
                # unexpected first transmission out of the message-type test.
                if message == "request" and not any(p["direction"] == "server" for p in packets):
                    if not raw or NAMES.get(raw[0]) != "solicit":
                        raise AssertionError("expected discovery before Request")
                    response = offer(raw)
                    peer.sendto(response, sender)
                    packets.append(dict(time=time.monotonic(), iface=INTERFACE, direction="server",
                                        src=LINK, dst=sender[0], sport=547, dport=sender[1],
                                        payload=response.hex()))
                else:
                    indices.append(len(packets) - 1)
                    if on_last and len(indices) == count:
                        on_last(peer, sender, raw, packets)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return packets, indices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", choices=IDS, default=IDS[0])
    parser.add_argument("--message", choices=MESSAGES, default="solicit")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    config = Path("/etc/dhcomply.conf")
    if config.exists() or Path(f"/var/lib/dhcp/lease_{INTERFACE}.json").exists():
        parser.error("use a fresh container without prior dhcomply configuration or leases")
    iface = configure_link()
    with config.open("x") as output:
        output.write("IANA IAID: 1234\n")
    try:
        packets, indices = capture(binary, iface, args.message, 3 if args.case.endswith("008") else 1,
                                   args.timeout)
        starts = [indices[0]]
        if args.case.endswith("007"):
            for _ in range(2):
                extra, marks = capture(binary, iface, args.message, 1, args.timeout)
                starts.append(len(packets) + marks[0])
                packets.extend(extra)
        expected_options = [1, 8]
        if args.message == "information_request":
            expected_options.append(6)
        else:
            expected_options.append(3)
        if args.message == "request":
            expected_options.append(2)
        data = dict(case=args.case, message=args.message, dut=str(binary),
                    packets=packets, before=dict(enabled_option_codes=expected_options),
                    after=dict(exchange_starts=starts, outgoing_indices=indices))
        path = args.evidence / args.case / (args.message + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return subprocess.call([sys.executable, str(ROOT / "run.py"), "--case", args.case,
                                "--message", args.message, "--evidence", str(args.evidence)])
    finally:
        config.unlink()
        remove_link(iface)


if __name__ == "__main__":
    sys.exit(main())
