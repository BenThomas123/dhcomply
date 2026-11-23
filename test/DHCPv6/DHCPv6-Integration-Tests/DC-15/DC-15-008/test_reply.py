from lease_checks import duid, bindings, installed, no_use


def check(trace):
    q = trace.client("request")[0]
    bad, good = trace.server("reply")[:2]
    assert q.index < bad.index < good.index and bad.xid == good.xid == q.xid
    assert duid(bad) != duid(q) == duid(good)
    assert set(bindings(bad)).isdisjoint(bindings(good)) and bindings(bad)
    no_use(trace, set(bindings(bad)))
    installed(trace, good)
