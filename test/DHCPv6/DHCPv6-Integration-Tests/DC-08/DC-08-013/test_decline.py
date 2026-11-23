from lease_checks import bindings, installed


def check(trace):
    p = trace.client("decline")[0]
    grants = [q for q in trace.server("reply") if q.index > p.index and bindings(q)]
    assert grants and not (installed(trace, grants[-1]) & set(bindings(p)))
