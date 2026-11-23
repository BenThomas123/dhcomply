from lease_checks import associations, bindings, leases, response


def check(trace):
    p = response(trace, "request")
    invalid = {(k, i) for k, i, t1, t2, _ in associations(p) if t1 > t2 > 0}
    assert invalid and any(k[:2] not in invalid and k in leases(trace.after) for k in bindings(p))
    assert all(k[:2] not in invalid for k in leases(trace.after))
