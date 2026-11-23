from lease_checks import duid


def check(trace):
    p = trace.client("solicit")[0]
    data = duid(p)
    assert data == bytes.fromhex(trace.before["known_duid_vector"])
