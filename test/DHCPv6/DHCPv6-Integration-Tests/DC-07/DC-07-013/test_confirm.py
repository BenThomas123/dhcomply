def check(trace):
    p = trace.client("confirm")[0]
    assert not p.options(2)
