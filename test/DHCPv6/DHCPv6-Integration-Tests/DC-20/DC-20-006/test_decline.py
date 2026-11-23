from lease_checks import bindings, leases, events, no_use


def check(trace):
    p = trace.client("decline")[0]
    failed = {e["resource"] for e in events(trace, "dad_failed") if e["time"] <= p.time}
    keys = set(bindings(p))
    assert failed and {k[2] for k in keys} == failed
    assert not p.options(25)
    no_use(trace, keys)
    grants = [q for q in trace.server("reply") if q.index < p.index and bindings(q)]
    assert grants, "Missing address-bearing lease Reply before DAD"
    addresses = {k for k in bindings(grants[-1]) if k[0] == "na"}
    assert len(keys) == 1 and keys < addresses
    for key in addresses - keys:
        assert any(e["resource"] == key[2] and e["time"] > grants[-1].time
                   for e in events(trace, "dad_complete"))
        assert key in leases(trace.after) and key[2] in trace.after["addresses"]
