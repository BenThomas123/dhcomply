from lease_checks import bindings, events, no_use


def check(trace):
    p = trace.client("decline")[0]
    failed = {e["resource"] for e in events(trace, "dad_failed") if e["time"] <= p.time}
    keys = set(bindings(p))
    assert failed and {k[2] for k in keys} == failed
    assert not p.options(25)
    no_use(trace, keys)
