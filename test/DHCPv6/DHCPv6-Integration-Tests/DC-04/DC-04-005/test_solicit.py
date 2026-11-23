from lease_checks import associations, leases, first_after


def check(trace):
    p = first_after(trace, "reboot", "solicit")
    known = {k[1] for k in leases(trace.before) if k[0] == "na"}
    assert known and {i for k, i, *_ in associations(p) if k == "na"} == known
