from lease_checks import bindings, leases, events, preserved, no_use


def check(trace):
    p = trace.client("decline")[0]
    failed = {e["resource"] for e in events(trace, "dad_failed") if e["time"] <= p.time}
    keys = set(bindings(p))
    assert failed and {k[2] for k in keys} == failed
    assert not p.options(25)
    no_use(trace, keys)
    remaining = set(leases(trace.before)) - keys
    prefixes = {k for k in remaining if k[0] == "pd"}
    assert prefixes and all(k[2] in trace.after["prefixes"] for k in prefixes)
    preserved(trace, remaining)
