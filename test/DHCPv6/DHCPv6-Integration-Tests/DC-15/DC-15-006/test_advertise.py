def check(trace):
    first, second = trace.client("solicit")[:2]
    p = trace.server("advertise")[0]
    assert first.iface != second.iface == p.iface and first.xid == p.xid != second.xid
    assert not any(q.name == "request" and q.index > p.index and q.iface == p.iface and q.options(2) == p.options(2) for q in trace.packets)
    assert trace.client("solicit")[-1].index > p.index
