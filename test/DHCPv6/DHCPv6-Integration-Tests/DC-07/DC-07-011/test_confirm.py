from lease_checks import associations, leases, first_after


def check(trace):
    p = first_after(trace, "link_change", "confirm")
    assert any(k[0] == "na" for k in leases(trace.before))
    assert any(k == "na" for k, *_ in associations(p))
