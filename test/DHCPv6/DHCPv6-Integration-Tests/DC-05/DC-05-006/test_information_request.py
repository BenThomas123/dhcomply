def check(trace):
    p = trace.client("information_request")[0]
    assert not p.options(3) and not p.options(25)
