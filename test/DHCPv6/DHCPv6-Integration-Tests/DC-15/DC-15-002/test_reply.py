from lease_checks import leases


def check(trace):
    original = trace.client("renew")[0]
    current = trace.client("rebind")[0]
    stale = trace.server("reply")[-1]
    assert original.index < current.index < stale.index and stale.xid == original.xid != current.xid
    assert leases(trace.after) == leases(trace.before)
    assert trace.client("rebind")[-1].index > stale.index
