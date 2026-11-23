from lease_checks import associations, leases, response, status


def check(trace):
    p = response(trace, "request")
    assert status(p) == 1 and len(associations(p)) >= 2
    assert leases(trace.after) == leases(trace.before)
