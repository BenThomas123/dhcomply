from lease_checks import one, duid, associations, offers


def check(trace):
    p = trace.client("request")[0]
    candidates, chosen = offers(trace)
    duid(p)
    assert one(p, 2) == duid(chosen, 2) and len(one(p, 8)) == 2
    assert associations(p) and not p.options(14)
