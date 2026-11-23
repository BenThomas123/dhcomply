from lease_checks import bindings, leases


def check(trace):
    p = trace.client("renew")[0]
    previous = leases(trace.before)
    assert len(previous) >= 2 and set(bindings(p)) == set(previous)
