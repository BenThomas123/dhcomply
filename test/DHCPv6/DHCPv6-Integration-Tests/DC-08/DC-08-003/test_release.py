from lease_checks import bindings, events, no_use


def check(trace):
    p = trace.client("release")[0]
    keys = {k for k in bindings(p) if k[0] == "na"}
    no_use(trace, keys)
    for _, _, address in keys:
        assert any(e["resource"] == address and e["time"] <= p.time for e in events(trace, "address_removed"))
        assert not any(q.src == address and q.time >= p.time for q in trace.packets)
