from lease_checks import associations, leases, response, preserved, first_after, status


def check(trace):
    p = first_after(trace, "reboot", "confirm")
    assert any(k[0] == "na" for k in leases(trace.before))
    assert any(k == "na" for k, *_ in associations(p))
    assert status(response(trace, "confirm")) == 0
    preserved(trace, set(leases(trace.before)))
