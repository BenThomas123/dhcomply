"""IPv6 Ready Logo DHCP_Conf.1.3.1, client Reply reception, parts A–G."""

from conformance import Inconclusive, tlvs


def associations(packet):
    """Index nested TLVs by association type and IAID."""
    values = {}
    for code in (3, 25):
        for raw in packet.options(code):
            if len(raw) < 12:
                raise ValueError("incomplete IA header")
            key = (code, raw[:4])
            if key in values:
                raise ValueError("duplicate association")
            values[key] = (int.from_bytes(raw[4:8], "big"), list(tlvs(raw[12:])))
    return values


def check_reply(trace, part):
    request_name = {"a": "request", "b": "request", "c": "request", "d": "renew",
                    "e": "rebind", "f": "renew", "g": "rebind"}[part]
    reply = trace.packets[trace.before["stimulus_index"]]
    if reply.direction != "server" or reply.name != "reply":
        raise Inconclusive("stimulus marker must identify the server Reply")
    requests = [p for p in trace.client(request_name) if p.index < reply.index
                and p.xid == reply.xid and p.iface == reply.iface]
    if not requests:
        raise Inconclusive("no originating exchange for marked Reply")
    request = requests[-1]
    if (len(reply.options(2)) != 1 or not reply.options(2)[0] or
            len(request.options(1)) != 1 or reply.options(1) != request.options(1) or
            (request.options(2) and request.options(2) != reply.options(2))):
        raise Inconclusive("Reply identifiers do not match this exchange")
    old, new = associations(request), associations(reply)
    later = [p for p in trace.packets if p.index > reply.index
             and p.iface == reply.iface and p.direction == "client"]
    if part in ("a", "b"):
        code = 1 if part == "a" else 4
        if [v[:2] for v in reply.options(13)] != [code.to_bytes(2, "big")]:
            raise Inconclusive("wrong top-level Reply status")
    if part == "b":
        assert later, "client did not restart discovery or retry Request"
        p = later[0]
        if p.name == "solicit":
            assert p.dst == "ff02::1:2"
        else:
            assert p.name == "request" and p.xid == request.xid
            assert not any(c == 5 for _, opts in associations(p).values() for c, _ in opts)
        return
    if part == "c":
        changed = new.keys() - old.keys()
        if not changed or not all(new[key][0] == 50 for key in changed):
            raise Inconclusive("Reply must offer a different association with T1 of 50 seconds")
        renews = [p for p in later if p.name == "renew"]
        assert renews and changed <= associations(renews[0]).keys(), "Renew lacks assigned IA"
        assert renews[0].options(2) == reply.options(2)
        assert renews[0].time >= reply.time + 50 - trace.before["clock_tolerance"]
        return
    if part in ("d", "e"):
        nobinding = {k for k, (_, opts) in new.items()
                     if any(c == 13 and v[:2] == b"\x00\x03" for c, v in opts)}
        if not old or not old.keys() <= nobinding:
            raise Inconclusive("missing IA-specific NoBinding in stimulus")
        assert later and later[0].name == "request", "expected Request recovery"
        recovery = [p for p in later if p.name == "request" and p.options(2) == reply.options(2)]
        assert old.keys() <= {k for p in recovery for k in associations(p)}
        assert not any(p.name == request_name and p.xid == request.xid for p in later)
        return
    if part in ("f", "g") and (not old or old.keys() & new.keys()):
        raise Inconclusive("Reply must omit the requested associations")
    retries = [p for p in later if p.name == request_name and p.xid == request.xid]
    assert retries, f"missing retransmitted {request_name}"
    times = [request.time] + [p.time for p in retries]
    floor = trace.before["minimum_retry_spacing"]
    if floor <= 0:
        raise Inconclusive("a positive minimum retry interval is required")
    assert all(b - a >= floor for a, b in zip(times, times[1:])), "retry spacing too short"
    if part == "a":
        limit = trace.before["exchange_deadline"]
        if limit <= request.time or trace.after["time"] <= limit:
            raise Inconclusive("observe until after the Request retry window")
        assert retries[-1].time <= limit, "Request continued past its deadline"
