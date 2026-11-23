from lease_checks import duid


def check(trace):
    p = trace.client("renew")[0]
    assert duid(p, 2).hex() == trace.before["server_duid"]
