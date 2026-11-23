from lease_checks import leases, response, installed


def check(trace):
    p = response(trace, "request")
    keys = installed(trace, p)
    assert any(k[0] == "pd" and k not in leases(trace.before) for k in keys)
