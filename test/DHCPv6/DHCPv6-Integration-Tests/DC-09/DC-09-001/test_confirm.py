from lease_checks import leases, response, preserved, status


def check(trace):
    p = response(trace, "confirm")
    assert status(p) == 0
    preserved(trace, leases(trace.before).keys())
