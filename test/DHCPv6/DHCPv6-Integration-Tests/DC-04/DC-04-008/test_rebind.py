from lease_checks import associations


def check(trace):
    p = trace.client("rebind")[0]
    initial = trace.client("solicit")[0]
    assert initial.index < p.index
    current = {(k, i) for k, i, *_ in associations(p)}
    assert current and current <= {(k, i) for k, i, *_ in associations(initial)}
