def check(trace):
    p = trace.client("rebind")[0]
    assert not p.options(2)
