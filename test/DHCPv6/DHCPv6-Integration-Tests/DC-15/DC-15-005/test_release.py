from lease_checks import duid, leases


def check(trace):
    p = trace.client("release")[0]
    bad = trace.server("reply")[0]
    assert duid(p) and not bad.options(1) and bad.xid == p.xid and bad.index > p.index
    assert leases(trace.before) == leases(trace.after)
    assert trace.client("release")[-1].index > bad.index
