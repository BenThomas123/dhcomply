"""Observations for RFC 9915 timing cases. All times use the capture monotonic clock.

before.start is the exchange trigger; after.end is the last observation time.
For Renew/Rebind provide before.t2_at and before.expiry_at as absolute deadlines.
before.random_factors is the injected RAND sequence (signed fractions).
before.leases and after.leases contain lease identities (not remaining lifetimes).
before/after fields in individual tests are inputs, clocks and OS observations,
never an externally supplied test verdict. Capture every send on the tested link.
"""

from itertools import pairwise

from conformance import Inconclusive, tlvs


IRT = dict(solicit=1, request=1, confirm=1, renew=10, rebind=10,
           decline=1, release=1, information_request=1)
MRT = dict(solicit=3600, request=30, confirm=4, renew=600, rebind=600,
           decline=0, release=0, information_request=3600)
MRC = dict(request=10, decline=4, release=4)
# Tolerance for a controlled scheduler with millisecond-resolution capture timestamps.
EPS = 0.011


def require(condition, reason):
    if not condition:
        raise Inconclusive(reason)


def number(packet, code, width):
    values = packet.options(code)
    assert len(values) == 1, f"expected one option {code}, got {len(values)}"
    assert len(values[0]) == width, f"option {code} has incorrect width"
    return int.from_bytes(values[0], "big")


def exchange(trace, name, minimum=1):
    packets = trace.client(name)
    first = packets[0]
    selected = [p for p in packets if (p.iface, p.xid) == (first.iface, first.xid)]
    assert len(selected) >= minimum, f"expected {minimum} {name} transmissions on {first.iface}"
    return selected


def elapsed(trace, name, mode):
    packets = exchange(trace, name, 1 if mode in ("present", "initial") else 3)
    start = trace.before["start"] if mode != "present" else 0
    if mode in ("initial", "present"):
        packets = packets[:1]
    for p in packets:
        value = number(p, 8, 2)
        if mode != "present":
            assert p.time >= start
            expected = min(int((p.time - start) * 100), 65535)
            assert abs(value - expected) <= 1, (value, expected)
            if p.time - start >= 655.35 + EPS:
                assert value == 65535
    if mode == "saturated":
        require(packets[-1].time - start > 655.35 + EPS, "capture must reach saturation")


def silent(trace, packets):
    p = packets[0]
    require(not any(m.name in ("advertise", "reply") and m.iface == p.iface
                    and m.xid == p.xid and m.index > p.index for m in trace.packets),
            "a no-response exchange is required")


def deadline(trace, name, start):
    if name == "confirm":
        return start + 10
    if name == "renew":
        return trace.before["t2_at"]
    if name == "rebind":
        return trace.before["expiry_at"]
    return None


def intervals(packets):
    return [b.time - a.time for a, b in pairwise(packets)]


def schedule(trace, name, mode):
    packets = exchange(trace, name, 2 if mode == "first" else 3)
    silent(trace, packets)
    gaps = intervals(packets)
    cap = MRT[name]
    if mode == "configured":
        cap = trace.before["effective_mrt_seconds"]
        require(cap > 0, "supply the configured maximum retry interval")
    factors = trace.before["random_factors"] if mode in ("first", "later", "capped", "jitter") else None
    if factors is not None:
        require(len(factors) >= len(gaps), "missing injected RAND samples")
    capped = False
    for i, actual in enumerate(gaps):
        base = IRT[name] if i == 0 else 2 * gaps[i - 1]
        jitter_base = IRT[name] if i == 0 else gaps[i - 1]
        low = base - .1 * jitter_base
        high = base + .1 * jitter_base
        if i == 0 and name == "solicit":
            assert actual > IRT[name]
        if factors is None:
            ordinary = low - EPS <= actual <= high + EPS and (not cap or actual <= cap + EPS)
            capped_interval = cap and high > cap and .9 * cap - EPS <= actual <= 1.1 * cap + EPS
            assert ordinary or capped_interval, (i, actual, low, high, cap)
        else:
            factor = factors[i]
            require(-.1 <= factor <= .1, "invalid injected RAND")
            expected = base + factor * jitter_base
            if cap and expected > cap:
                expected = cap * (1 + factor)
                capped = True
            assert abs(actual - expected) <= 3 * EPS, (actual, expected)
    if mode == "capped":
        require(capped, "schedule never reached MRT")
    if mode == "configured":
        require(len(gaps) >= 3 and max(gaps[:-1]) >= cap / 2,
                "exercise the configured cap before ending the capture")
        assert .9 * cap - EPS <= gaps[-1] <= 1.1 * cap + EPS
    if mode == "limits":
        if name in MRC:
            assert len(packets) <= MRC[name]
        stop = deadline(trace, name, packets[0].time)
        if stop is not None:
            assert packets[-1].time <= stop + EPS


def count_limit(trace, name):
    packets = exchange(trace, name)
    silent(trace, packets)
    # Observe through the longest possible complete MRC schedule, including final wait.
    upper = IRT[name] * 1.1
    window = 0
    for _ in range(MRC[name]):
        window += upper
        upper = min(upper * 2.1, MRT[name] * 1.1) if MRT[name] else upper * 2.1
    require(trace.after["end"] >= packets[0].time + window, "capture ended before retry exhaustion")
    assert len(packets) == MRC[name], (len(packets), MRC[name])


def duration_limit(trace, name):
    packets = exchange(trace, name)
    silent(trace, packets)
    end = deadline(trace, name, packets[0].time)
    require(trace.after["end"] > end + EPS, "capture must extend past deadline")
    assert packets[-1].time <= end + EPS


def unlimited(trace, name):
    packets = exchange(trace, name)
    silent(trace, packets)
    minimum = trace.before["observe_retries"]
    require(minimum > 10, "choose a horizon beyond the bounded Request schedule")
    assert len(packets) >= minimum + 1


def same_retransmission(trace, name, all_options):
    packets = trace.client(name)
    require(len(packets) >= 3, "capture three consecutive copies")
    first = packets[0]
    silent(trace, [first])
    stable = [1, 2, 3, 25]
    for p in packets[1:]:
        assert (p.iface, p.xid) == (first.iface, first.xid)
        if all_options:
            # Stable-lease fixture: no lease expires or changes during this capture.
            assert [(c, v) for c, v in tlvs(p.raw[4:]) if c != 8] == [
                (c, v) for c, v in tlvs(first.raw[4:]) if c != 8]
        else:
            assert all(p.options(c) == first.options(c) for c in stable)


def response(trace, request, kind="reply"):
    matches = [p for p in trace.server(kind) if p.iface == request.iface
               and p.index > request.index and p.xid == request.xid]
    require(matches, f"capture lacks correlated {kind} for {request.name}")
    return matches[0]


def end_on_success(trace, name):
    sends = exchange(trace, name, 2)
    kind = "advertise" if name == "solicit" else "reply"
    reply = response(trace, sends[0], kind)
    require(sends[1].index < reply.index, "respond after at least one retry")
    require(not any(v[:2] != b"\x00\x00" for v in reply.options(13)), "need successful response")
    require(trace.after["end"] > reply.time + 2.1 * (sends[1].time - sends[0].time),
            "observe beyond next retry opportunity")
    assert not any(p.index > reply.index for p in sends)


def recovery(trace):
    count_limit(trace, "request")
    req = exchange(trace, "request")
    action = trace.before["request_recovery"]  # restart, alternate, or stop per DUT policy
    require(action in {"restart", "alternate", "stop"}, "unknown configured recovery policy")
    following = [p for p in trace.packets if p.index > req[-1].index and p.name in IRT]
    if action == "stop":
        assert not following
    elif action == "restart":
        assert following and following[0].name == "solicit"
    else:
        assert following and following[0].name == "request"
        assert following[0].options(2) != req[0].options(2)


def cap_value(trace, exchange_name, source, condition):
    code = 82 if exchange_name == "solicit" else 83
    previous = trace.before.get("previous_cap", 3600)
    responses = [p for p in trace.packets if p.name in source.split("+")]
    require(responses, f"capture lacks {source}")
    if condition == "default":
        require(all(not p.options(code) for p in responses), "override unexpectedly present")
        cap = 3600
    else:
        values = [number(p, code, 4) for p in responses if p.options(code)]
        require(values, "capture lacks server-provided cap")
        if condition in ("conflict", "conflict_failure"):
            require(len(set(values)) > 1 and all(60 <= n <= 86400 for n in values),
                    "two different valid offers required")
            require(len({tuple(p.options(2)) for p in responses if p.options(code)}) >= 2,
                    "two different servers required")
            cap = 3600
        elif isinstance(condition, int):
            require(values == [condition], f"this variant needs option value {condition}")
            cap = condition if 60 <= condition <= 86400 else previous
        else:
            require(len(set(values)) == 1 and 60 <= values[0] <= 86400, "need one valid override")
            require(values[0] != previous, "override must differ from previous cap")
            cap = values[0]
    if condition in ("failure", "conflict_failure"):
        require(any(v[:2] != b"\x00\x00" for p in responses for v in p.options(13)),
                "server failure status required")
    require(len({p.iface for p in responses}) == 1, "isolate server responses to the tested interface")
    observed = [p for p in trace.client(exchange_name) if p.index > responses[-1].index
                and p.iface == responses[-1].iface]
    require(len(observed) >= 3, "capture retries through steady cap")
    assert len({p.xid for p in observed}) == 1
    a, b = intervals(observed)[-2:]
    assert .9 * cap - EPS <= a <= 1.1 * cap + EPS and .9 * cap - EPS <= b <= 1.1 * cap + EPS


def unchanged_leases(trace):
    old = trace.before["leases"]
    require(old, "start with valid lease identities")
    assert trace.after["leases"] == old
