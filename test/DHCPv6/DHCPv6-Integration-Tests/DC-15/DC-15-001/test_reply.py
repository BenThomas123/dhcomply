from lease_checks import leases


def check(trace):
    original = trace.client("request")[0]
    current = trace.client("renew")[0]
    stale = trace.server("reply")[-1]
    assert original.index < current.index < stale.index and stale.xid == original.xid != current.xid
    assert leases(trace.after) == leases(trace.before)
    assert trace.client("renew")[-1].index > stale.index
