from lease_checks import one, bindings


def check(trace):
    p = trace.server("advertise")[0]
    assert not bindings(p)
    assert trace.after["sol_max_rt"] == int.from_bytes(one(p, 82), "big")
    assert trace.client("solicit")[-1].index > p.index
    assert not any(q.name == "request" and q.options(2) == p.options(2) for q in trace.packets)
