from lease_checks import leases, response, no_use, status


def check(trace):
    p = response(trace, "confirm")
    assert status(p) == 4 and trace.client("solicit")[-1].index > p.index
    no_use(trace, {k for k in leases(trace.before) if k[0] == "na"})
