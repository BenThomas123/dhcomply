from lease_checks import duid


def check(trace):
    p = trace.client("solicit")[0]
    assert not trace.before["identity_present"]
    assert duid(p) == bytes.fromhex(trace.after["client_duid"])
