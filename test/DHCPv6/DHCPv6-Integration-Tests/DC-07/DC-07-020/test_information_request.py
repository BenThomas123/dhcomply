from lease_checks import associations, leases, first_after


def check(trace):
    p = first_after(trace, "reconnect", "information_request")
    assert not leases(trace.before) and not associations(p)
