from lease_checks import bindings, leases


def check(trace):
    p = trace.client("confirm")[0]
    previous = leases(trace.before)
    addresses = {k for k in previous if k[0] == "na"}
    assert len(addresses) >= 2 and set(bindings(p)) == addresses
