from lease_checks import bindings, leases, response, installed


def check(trace):
    p = response(trace, "rebind")
    records = bindings(p)
    previous = leases(trace.before)
    keys = installed(trace, p)
    assert keys & previous.keys() and keys - previous.keys()
    assert any(k[:2] == j[:2] for k in keys - previous.keys() for j in previous)
