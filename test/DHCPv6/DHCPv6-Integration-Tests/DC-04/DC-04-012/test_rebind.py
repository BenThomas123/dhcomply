from lease_checks import duid, bindings, leases, first_after


def check(trace):
    p = first_after(trace, "restart", "rebind")
    assert duid(p) == bytes.fromhex(trace.before["client_duid"])
    assert set(bindings(p)) == set(leases(trace.before)) and bindings(p)
