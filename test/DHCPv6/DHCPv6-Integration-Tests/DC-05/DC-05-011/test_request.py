from lease_checks import associations, response, installed


def check(trace):
    p = response(trace, "request")
    keys = installed(trace, p)
    assert any(sum(key[:2] == (kind, iaid) for key in keys) >= 2
               for kind, iaid, *_ in associations(p) if kind == "na")
