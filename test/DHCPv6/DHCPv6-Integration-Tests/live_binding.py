"""Exercise normal IPv6 address acquisition against the compiled client."""
import argparse
from ipaddress import IPv6Address
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from conformance import tlvs
from live import INTERFACE, LINK, ROOT, capture, configure_link, offer, option, remove_link


CASES = {
    "DC-04-009": ("solicit",),
    "DC-05-007": ("request", "solicit"),
    "DC-06-001": ("request",),
    "DC-09-002": ("request",),
}
LEASE = Path("/var/lib/dhcp") / f"lease_{INTERFACE}.json"


def addresses():
    result = []
    for row in Path("/proc/net/if_inet6").read_text().splitlines():
        addr, _, _, _, flags, iface = row.split()
        if iface == INTERFACE and not int(flags, 16) & 0x48:
            result.append(str(IPv6Address(bytes.fromhex(addr))))
    return result


def lease_state():
    try:
        doc = json.loads(LEASE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    return [dict(kind="na", iaid=int(entry["iaid"], 16), resource=entry["address"])
            for entry in doc["leases"] if entry["type"] == "IANA"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--case", choices=tuple(CASES), required=True)
    parser.add_argument("--message", choices=("request", "solicit"), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if args.message not in CASES[args.case]:
        parser.error("message does not apply to this case")
    binary = args.binary.resolve(strict=True)
    identity = args.case == "DC-04-009"
    rapid = args.message == "solicit" and not identity
    if not identity and not (shutil.which("sudo") and shutil.which("ip")):
        parser.error("dhcomply needs sudo and iproute2 in the test image for OS address installation")
    config = Path("/etc/dhcomply.conf")
    if config.exists() or LEASE.exists():
        parser.error("start with no configuration or lease in a disposable offline container")
    iface = configure_link()
    try:
        LEASE.parent.mkdir(parents=True, exist_ok=True)
        with config.open("x") as file:
            file.write("IANA IAID: 1234\n")
            if rapid:
                file.write("send dhcp6.rapid-commit\n")
        before = dict(leases=lease_state(), addresses=addresses(), ia_kinds=["na"])

        def grant(peer, sender, raw, rows):
            assert raw[0] == (1 if rapid else 3), "unexpected client message before grant"
            parts = list(tlvs(offer(raw)[4:]))
            response = b"\x07" + raw[1:4] + b"".join(option(c, v) for c, v in parts if c != 7)
            if rapid:
                assert (14, b"") in list(tlvs(raw[4:])), "missing Rapid Commit in Solicit"
                response += option(14, b"")
            when = time.monotonic()
            peer.sendto(response, sender)
            rows.append(dict(time=when, direction="server", iface=INTERFACE, src=LINK, sport=547,
                             dst=sender[0], dport=sender[1], payload=response.hex()))
            end = when + 5
            while time.monotonic() < end:
                if lease_state() and (identity or "2001:db8::77" in addresses()):
                    break
                time.sleep(0.05)

        first = "solicit" if rapid else "request"
        rows, _ = capture(binary, iface, first, 1, 15, on_last=grant)
        after = dict(leases=lease_state(), addresses=addresses(), prefixes=[])
        if identity:
            if not after["leases"]:
                raise RuntimeError("no completed first acquisition observed")
            # Leave the interface and MAC in place; clear only this driver's lease
            # so a fresh process initiates discovery instead of confirming it.
            LEASE.unlink()
            more, _ = capture(binary, iface, "solicit", 1, 15)
            rows.extend(more)
        result = dict(case=args.case, message=args.message, dut=str(binary),
                      before=before, after=after, packets=rows)
        folder = args.evidence / args.case
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (args.message + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        return subprocess.call([sys.executable, "-B", str(ROOT / "run.py"), "--case", args.case,
                                "--message", args.message, "--evidence", str(args.evidence)])
    finally:
        config.unlink(missing_ok=True)
        LEASE.unlink(missing_ok=True)
        remove_link(iface)


if __name__ == "__main__":
    sys.exit(main())
