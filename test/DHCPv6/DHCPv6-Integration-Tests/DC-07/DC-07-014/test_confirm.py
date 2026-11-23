from lease_checks import leases, response, preserved, status


def check(trace):
    p = response(trace, "confirm")
    assert status(p) == 0
    preserved(trace, set(leases(trace.before)))
    assert all(k[2] in trace.after["addresses"] for k in leases(trace.before) if k[0] == "na")
