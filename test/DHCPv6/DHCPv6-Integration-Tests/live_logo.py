"""Drive IPv6 Ready Logo DHCP_Conf.1.3.1 A–C against a real dhcomply process.

Run one part per disposable Linux container with --network none --cap-add
NET_ADMIN. Part A observes the whole default Request retry window (about
3.5 minutes). Part C waits for the actual 50-second lease timer. Run --help
for the invocation. The evidence JSON can also be checked with run.py.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from conformance import tlvs
from live import GROUP, INTERFACE, LINK, ROOT, configure_link, offer, option, remove_link


# RFC 9915 default REQ_TIMEOUT, REQ_MAX_RT, and REQ_MAX_RC. Use the upper
# envelope of ten retry intervals, with a small allowance for capture timing.
REQUEST_RETRY_LIMIT = 210.0
OBSERVATION_SECONDS = {"A": REQUEST_RETRY_LIMIT + 5, "B": 5.0, "C": 60.0}


def reply_to(request, part):
    opts = dict(tlvs(request[4:]))
    header = b"\x07" + request[1:4] + option(1, opts[1]) + option(2, opts[2])
    if part == "A":
        return header + option(13, struct.pack("!H", 1))  # UnspecFail
    if part == "B":
        return header + option(13, struct.pack("!H", 4))  # NotOnLink
    old_iaid, = struct.unpack("!I", opts[3][:4])
    ia_header = struct.pack("!III", old_iaid ^ 1, 50, 90)
    address = socket.inet_pton(socket.AF_INET6, "2001:db8::78")
    return header + option(3, ia_header + option(5, address + struct.pack("!II", 120, 180)))


def send_response(peer, sender, raw):
    when = time.monotonic()
    size = peer.sendto(raw, sender)
    if size != len(raw):
        raise OSError("incomplete server response")
    return dict(time=when, direction="server", iface=INTERFACE, src=LINK, sport=547,
                dst=sender[0], dport=sender[1], payload=raw.hex())


def observe(binary, iface, part, log):
    before = {"clock_tolerance": 1.0, "minimum_retry_spacing": 0.85}
    packets = []
    deadline = time.monotonic() + 15.0
    stage = "solicit"
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
        peer.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        peer.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack("@I", iface))
        peer.bind(("::", 547))
        process = subprocess.Popen([str(binary), "N", INTERFACE], start_new_session=True,
                                   stdout=log, stderr=log)
        try:
            while time.monotonic() < deadline:
                peer.settimeout(min(0.25, max(0.001, deadline - time.monotonic())))
                try:
                    raw, controls, flags, sender = peer.recvmsg(65535, 128)
                except socket.timeout:
                    if process.poll() is not None:
                        break
                    continue
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise RuntimeError("incomplete UDP capture")
                meta = next(data for level, kind, data in controls
                            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO)
                destination, index = struct.unpack("@16sI", meta)
                if index != iface:
                    raise RuntimeError("unexpected capture interface")
                when = time.monotonic()
                packets.append(dict(time=when, direction="client", iface=INTERFACE,
                                    src=sender[0], sport=sender[1], dst=socket.inet_ntop(socket.AF_INET6, destination),
                                    dport=547, payload=raw.hex()))
                if stage == "solicit" and raw[:1] == b"\x01":
                    packets.append(send_response(peer, sender, offer(raw)))
                    stage = "request"
                elif stage == "request" and raw[:1] == b"\x03":
                    before["stimulus_index"] = len(packets)
                    packets.append(send_response(peer, sender, reply_to(raw, part)))
                    before["exchange_deadline"] = when + REQUEST_RETRY_LIMIT
                    deadline = when + OBSERVATION_SECONDS[part]
                    stage = "observe"
                elif stage == "observe" and (part == "B" or (part == "C" and raw[:1] == b"\x05")):
                    break
            end = time.monotonic()
            status = process.poll()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return dict(case="DHCP_Conf.1.3.1-" + part, message="reply", dut=str(binary), packets=packets,
                before=before, after=dict(time=end, client_exit_status=status))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--part", type=str.upper, choices=tuple(OBSERVATION_SECONDS), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    config = Path("/etc/dhcomply.conf")
    leases = Path("/var/lib/dhcp")
    lease = leases / f"lease_{INTERFACE}.json"
    if config.exists() or lease.exists():
        parser.error("use a fresh container with no DHCP client configuration or lease")
    iface = configure_link()
    leases.mkdir(parents=True, exist_ok=True)
    result_dir = args.evidence / ("DHCP_Conf.1.3.1-" + args.part)
    result_dir.mkdir(parents=True, exist_ok=True)
    with config.open("x") as stream:
        stream.write("IANA IAID: 1234\n")
    try:
        with (result_dir / "client.log").open("w") as log:
            result = observe(binary, iface, args.part, log)
        (result_dir / "reply.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return subprocess.call([sys.executable, str(ROOT / "run.py"), "--case", result["case"],
                                "--message", "reply", "--evidence", str(args.evidence)])
    finally:
        config.unlink()
        lease.unlink(missing_ok=True)
        remove_link(iface)


if __name__ == "__main__":
    sys.exit(main())
