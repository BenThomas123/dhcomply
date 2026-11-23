from lease_checks import duid, first_after


def check(trace):
    p = first_after(trace, "restart", "solicit")
    assert duid(p) == bytes.fromhex(trace.before["client_duid"])
