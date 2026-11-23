from lease_checks import duid, leases, preserved, status


def check(trace):
    p = trace.client("confirm")[0]
    replies = [q for q in trace.server("reply") if q.xid == p.xid and q.index > p.index and q.options(1) == p.options(1)]
    assert len(replies) >= 2 and status(replies[0]) == 4 and status(replies[1]) == 0 and duid(replies[0], 2) != duid(replies[1], 2)
    preserved(trace, leases(trace.before).keys())
