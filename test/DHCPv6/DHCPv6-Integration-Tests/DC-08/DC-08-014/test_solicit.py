from lease_checks import one, duid, associations


def check(trace):
    p = trace.client("solicit")[0]
    duid(p)
    assert one(p, 14) == b"" and len(one(p, 8)) == 2 and associations(p)
