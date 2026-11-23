from lease_checks import duid


def check(trace):
    p = trace.client("release")[0]
    assert duid(p).hex() == trace.before["client_duid"] and duid(p, 2).hex() == trace.before["server_duid"]
