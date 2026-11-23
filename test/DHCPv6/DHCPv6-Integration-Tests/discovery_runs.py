"""Collect and check early DHCPv6 exchanges from a real Linux dhcomply binary.

Run in the same disposable, offline container used by live.py. --list shows all
supported message/case pairs without starting a process or creating an interface.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from conformance import Trace
from live import INTERFACE, MESSAGES, ROOT, capture, configure_link, remove_link


# A silent peer elicits retransmissions; Request uses live.capture's normal
# Advertise handshake. Capture sizes indicate the evidence needed by each check.
CASES = {
    "DC-03-001": (MESSAGES, 1), "DC-03-002": (MESSAGES, 1),
    "DC-03-003": (MESSAGES, 3), "DC-03-010": (MESSAGES, 3),
    "DC-03-011": (MESSAGES, 3),
    "DC-04-003": (("solicit",), 1),
    "DC-04-010": (("solicit",), 1),
    "DC-10-001": (MESSAGES, 1), "DC-10-002": (MESSAGES, 1),
    "DC-10-003": (("solicit", "request", "information_request"), 1),
    "DC-10-004": (MESSAGES, 1), "DC-10-005": (MESSAGES, 1),
    "DC-10-006": (("solicit",), 1), "DC-10-007": (("information_request",), 1),
    "DC-10-008": (MESSAGES, 1), "DC-10-020": (MESSAGES, 1),
    "DC-12-001": (MESSAGES, 1), "DC-17-012": (("solicit",), 2),
    "DC-21-001": (MESSAGES, 1), "DC-21-002": (("information_request",), 1),
}
RESTART = {"DC-04-003"}


def collect(binary, iface, message, count, restart, timeout):
    rows, indices = capture(binary, iface, message, count, timeout)
    observation_end = time.monotonic()
    # Elapsed Time (RFC 9915 §21.9) is relative to the first transmission.
    # The capture stamps it independently of the option supplied by the DUT.
    first_time = rows[indices[0]]["time"]
    before = dict(start=first_time, reconfigure_accept=False,
                  requested_options=[23, 24], requested_option_codes=[23, 24])
    after = dict(end=observation_end, events=[])
    if message == "solicit":
        mac = (Path("/sys/class/net") / INTERFACE / "address").read_text().strip()
        before["known_duid_vector"] = "00030001" + mac.replace(":", "")
    if restart:
        original = Trace(dict(packets=rows, before=before, after=after)).client(message)[0]
        identifiers = original.options(1)
        assert len(identifiers) == 1, "original exchange did not provide one Client Identifier"
        before["client_duid"] = identifiers[0].hex()
        marker = time.monotonic()
        rows2, _ = capture(binary, iface, message, 1, timeout)
        rows.extend(rows2)
        after.update(end=time.monotonic(), events=[dict(kind="restart", time=marker)])
    return dict(dut=str(binary), packets=rows, before=before, after=after)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", help="catalog ID supported by this live driver")
    parser.add_argument("--message", choices=MESSAGES)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    selected = [(case, message, count) for case, (messages, count) in CASES.items()
                for message in messages if (not args.case or case == args.case)
                and (not args.message or message == args.message)]
    if not selected:
        parser.error("unsupported live scenario; use --list to see supported cases")
    if args.list:
        for case, message, _ in selected:
            print(case, message)
        return 0
    if not args.binary or not args.evidence or args.timeout <= 0:
        parser.error("provide --binary, --evidence, and a positive --timeout")
    binary = args.binary.resolve(strict=True)
    # Only create outputs for this capture. A failed run cannot leave an older
    # capture in place under the same ID and make it look freshly verified.
    outputs = {(case, msg): args.evidence / case / (msg + ".json") for case, msg, _ in selected}
    if any(path.exists() for path in outputs.values()):
        parser.error("choose an evidence directory without previous results for these cases")
    for case, msg, _ in selected:
        if not (ROOT / case.rsplit("-", 1)[0] / case / ("test_" + msg + ".py")).is_file():
            parser.error(f"missing catalog implementation for {case} {msg}")
    config = Path("/etc/dhcomply.conf")
    if config.exists() or Path(f"/var/lib/dhcp/lease_{INTERFACE}.json").exists():
        parser.error("use a disposable container without an existing client configuration or lease")
    iface = configure_link()
    snapshots = {}
    status = 0
    with config.open("x") as stream:
        stream.write("IANA IAID: 1234\ndns-servers\ndomain-search-list\n")
    try:
        for case, msg, count in selected:
            restart = case in RESTART
            key = (msg, count, restart)
            if key not in snapshots:
                snapshots[key] = collect(binary, iface, msg, count, restart, args.timeout)
            data = dict(snapshots[key], case=case, message=msg)
            path = outputs[case, msg]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            rc = subprocess.call([sys.executable, "-B", str(ROOT / "run.py"), "--case", case,
                                  "--message", msg, "--evidence", str(args.evidence)])
            if rc == 1 or not status:
                status = rc
    finally:
        config.unlink()
        remove_link(iface)
    return status


if __name__ == "__main__":
    sys.exit(main())
