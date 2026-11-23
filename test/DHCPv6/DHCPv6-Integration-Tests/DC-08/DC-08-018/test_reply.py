from lease_checks import one, leases


def check(trace):
    s = trace.client("solicit")[0]
    p = trace.server("reply")[0]
    assert one(s, 14) == b"" and (p.xid != s.xid or p.options(1) != s.options(1) or p.options(14) != [b""])
    assert trace.client("solicit")[-1].index > p.index and leases(trace.after) == leases(trace.before)
