from lease_checks import leases, response, installed


def check(trace):
    p = response(trace, "solicit")
    keys = installed(trace, p)
    assert any(k[0] == "na" and k not in leases(trace.before) for k in keys)
