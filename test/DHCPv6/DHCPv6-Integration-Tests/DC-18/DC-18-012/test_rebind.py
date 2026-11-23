from lease_checks import first_after, retry


def check(trace):
    p = first_after(trace, "link_change", "rebind")
    assert p.options(25)
    packets = [q for q in retry(trace, "rebind", 2) if q.xid == p.xid]
    assert trace.before["confirm_retry_min"] <= packets[1].time - p.time <= trace.before["confirm_retry_max"]
