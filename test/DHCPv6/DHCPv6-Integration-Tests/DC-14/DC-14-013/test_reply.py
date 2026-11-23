from lease_checks import duid, bindings, leases


def check(trace):
    s = trace.client("solicit")[0]
    assert s.options(14) == [b""]
    replies = [p for p in trace.server("reply") if p.index > s.index and p.xid == s.xid and p.options(14) == [b""] and duid(p) == duid(s)]
    assert len({duid(p, 2) for p in replies}) >= 2
    state = set(leases(trace.after))
    assert state and any(state == set(bindings(p)) and trace.after["server_duid"] == duid(p, 2).hex() for p in replies)
