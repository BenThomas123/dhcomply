from lease_checks import bindings, events, no_use


def check(trace):
    p = trace.client("release")[0]
    keys = {k for k in bindings(p) if k[0] == "pd"}
    no_use(trace, keys)
    for _, _, prefix in keys:
        assert any(e["delegated"] == prefix and e["time"] <= p.time and e["preferred"] == e["valid"] == 0 for e in events(trace, "downstream_ra"))
