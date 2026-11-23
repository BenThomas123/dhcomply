from lease_checks import bindings, events, no_use


def check(trace):
    packets = trace.client("decline")
    first = packets[0]
    keys = set(bindings(first))
    assert keys
    offers = [q for q in trace.server("reply") if first.index < q.index and keys <= bindings(q).keys()]
    assert offers, "Missing regrant of previously declined address"
    grant = offers[0]
    fresh = [p for p in packets if p.index > grant.index and p.xid != first.xid]
    assert fresh and keys == set(bindings(fresh[0]))
    for key in keys:
        assert any(grant.time <= e["time"] <= fresh[0].time and e["resource"] == key[2]
                   for e in events(trace, "dad_failed"))
    no_use(trace, keys)
