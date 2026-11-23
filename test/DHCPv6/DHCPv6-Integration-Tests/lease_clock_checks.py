"""Lease-clock observations: all *_at values are absolute monotonic seconds.

before/after.rfc3339_wall_seconds and before/after.monotonic are independent
numeric clock readings. before/after.remaining_seconds are observed remaining
lifetimes for the same lease. before.bucket_capacity and before.bucket_per_second
describe the DUT's configured token-bucket profile; do not assume RFC defaults.
before.busy_iface identifies the interface subjected to repeated failure.
"""
from collections import defaultdict
from ipaddress import IPv6Address, IPv6Network

from timing_checks import EPS, IRT, exchange, number, require, response, tlvs


def rate(trace, multiple=False):
    capacity = trace.before["bucket_capacity"]
    refill = trace.before["bucket_per_second"]
    require(capacity >= 1 and refill > 0, "valid configured token bucket required")
    links = defaultdict(list)
    for p in trace.packets:
        if p.name in IRT:
            links[p.iface].append(p)
    busy = trace.before["busy_iface"]
    require(len(links[busy]) > capacity, "observe enough traffic to exercise rate limiter")
    require(any(p.iface == busy and p.name in ("reply", "advertise") and
                any(len(v) >= 2 and int.from_bytes(v[:2], "big") != 0 for v in p.options(13))
                for p in trace.packets), "record the server failures on the busy interface")
    for link, packets in links.items():
        tokens = capacity
        last = packets[0].time
        for p in packets:
            tokens = min(capacity, tokens + (p.time - last) * refill)
            assert tokens >= 1 - EPS * refill, f"rate exceeded on {link}"
            tokens -= 1
            last = p.time
    if multiple:
        require(len(links) >= 2, "two active interfaces required")
        other = next(k for k in links if k != busy)
        replies = [p for p in trace.packets if p.name == "reply" and p.iface == other]
        assert any(c.xid == r.xid and links[busy][0].time <= c.time <= r.time <= links[busy][-1].time
                   for r in replies for c in links[other]), "second link did not complete a concurrent exchange"


def resources(packet):
    result = set()
    for container in (3, 25):
        for ia in packet.options(container):
            assert len(ia) >= 12
            for code, data in tlvs(ia[12:]):
                if code == 5:
                    assert len(data) >= 24
                    result.add(str(IPv6Address(data[:16])))
                if code == 26:
                    assert len(data) >= 25
                    result.add(str(IPv6Network((IPv6Address(data[9:25]), data[8]), strict=False)))
    return result


def expiry(trace, mode):
    if mode == "renew":
        t2 = trace.before["t2_at"]
        renews = trace.client("renew")
        require(renews[0].time < t2, "start before T2")
        assert renews[-1].time <= t2 + EPS
        first = trace.client("rebind")[0]
        assert first.iface == renews[0].iface and abs(first.time - t2) <= EPS
    elif mode == "last":
        times = list(trace.before["expiry_by_resource"].values())
        require(len(set(times)) >= 2, "distinct lease expirations required")
        last = max(times)
        rebind = trace.client("rebind")
        assert rebind[0].time < last and rebind[-1].time <= last + EPS
        assert any(p.name == "solicit" and p.iface == rebind[0].iface and p.time >= last
                   for p in trace.packets)
    else:
        expiries = trace.before["expiry_by_resource"]
        require(any("/" in r for r in expiries) and any("/" not in r for r in expiries),
                "include an address and a delegated prefix")
        candidates = [p for p in trace.client("rebind") if min(expiries.values()) < p.time < max(expiries.values())]
        assert candidates, "expected Rebind between the two expirations"
        for p in candidates:
            got = resources(p)
            for resource, end in expiries.items():
                assert (resource in got) == (end > p.time)


def wall_jump(trace, name):
    before, after = trace.before, trace.after
    wall = after["rfc3339_wall_seconds"] - before["rfc3339_wall_seconds"]
    elapsed = after["monotonic"] - before["monotonic"]
    require(elapsed >= 0 and abs(wall - elapsed) >= 60, "supply a substantial realtime clock jump")
    require(before["leases"] and before["leases"] == after["leases"], "observe same lease through jump")
    trace.client(name)
    assert abs(after["remaining_seconds"] - max(0, before["remaining_seconds"] - elapsed)) <= 1
