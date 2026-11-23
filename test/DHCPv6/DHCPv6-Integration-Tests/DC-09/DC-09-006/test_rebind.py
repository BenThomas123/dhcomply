from lease_checks import associations, leases, response, preserved


def check(trace):
    p = response(trace, "rebind")
    failed = {(k, i) for k, i, _, _, nested in associations(p) if any(c == 13 and v[:2] == bytes([0, 3]) for c, v in nested)}
    assert failed
    requests = [q for q in trace.client("request") if q.index > p.index]
    assert requests and failed <= {(k, i) for k, i, *_ in associations(requests[0])}
    preserved(trace, {k for k in leases(trace.before) if k[:2] not in failed})
