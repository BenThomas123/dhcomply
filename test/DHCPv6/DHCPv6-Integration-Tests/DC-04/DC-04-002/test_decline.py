from lease_checks import duid


def check(trace):
    p = trace.client("decline")[0]
    assert duid(p) == bytes.fromhex(trace.before["client_duid"])
