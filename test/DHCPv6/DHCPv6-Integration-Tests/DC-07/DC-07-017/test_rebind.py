from lease_checks import associations, leases, first_after


def check(trace):
    p = first_after(trace, "link_change", "rebind")
    assert any(k[0] == "pd" for k in leases(trace.before))
    assert any(k == "pd" for k, *_ in associations(p))
