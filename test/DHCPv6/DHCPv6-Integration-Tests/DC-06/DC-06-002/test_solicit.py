from lease_checks import one, duid, associations


def check(trace):
    p = trace.client("solicit")[0]
    duid(p)
    assert len(one(p, 8)) == 2
    oro = one(p, 6)
    assert len(oro) >= 2 and len(oro) % 2 == 0
    assert {k for k, *_ in associations(p)} == set(trace.before["ia_kinds"])
