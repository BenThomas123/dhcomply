from lease_checks import leases, offers


def check(trace):
    candidates, chosen = offers(trace)
    q = trace.client("request")[0]
    s = trace.client("solicit")[0]
    p = trace.server("reply")[-1]
    assert p.index > q.index and p.xid == s.xid != q.xid and p.options(14) == [b""]
    assert leases(trace.after) == leases(trace.before) and trace.client("request")[-1].index > p.index
