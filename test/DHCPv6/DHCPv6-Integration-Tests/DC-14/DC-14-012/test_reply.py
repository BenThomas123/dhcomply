from lease_checks import duid, bindings, leases


def check(trace):
    q = trace.client("solicit")[0]
    p = trace.server("reply")[0]
    assert q.index < p.index and q.xid == p.xid and duid(q) == duid(p)
    assert not q.options(14) and p.options(14) == [b""]
    assert bindings(p) and not leases(trace.after)
    assert trace.client("solicit")[-1].index > p.index or any(m.name == "request" and m.index > p.index for m in trace.packets)
