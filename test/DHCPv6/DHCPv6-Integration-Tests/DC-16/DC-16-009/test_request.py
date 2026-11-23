from lease_checks import associations, response, mixed_status


def check(trace):
    p = response(trace, "request")
    mixed_status(trace, p, "na", 2)
    assert len({i for k, i, *_ in associations(p) if k == "na"}) >= 2
