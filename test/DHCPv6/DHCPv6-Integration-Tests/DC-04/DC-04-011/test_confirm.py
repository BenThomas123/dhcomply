from lease_checks import duid


def check(trace):
    p = trace.client("confirm")[0]
    vector = bytes.fromhex(trace.before["client_duid_vector"])
    assert duid(p) == vector
    if p.name in ("request", "renew", "release", "decline"):
        assert duid(p, 2) == bytes.fromhex(trace.before["server_duid_vector"])
