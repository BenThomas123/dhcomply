from resolver_checks import oro, updated


def check(trace):
    p = trace.client("information_request")[0]
    assert {23, 24} <= set(oro(p))
    assert not p.options(3) and not p.options(25)
    updated(trace, "information_request", 23, "current")
    updated(trace, "information_request", 24, "current")
