from lease_checks import one, response, installed


def check(trace):
    request = trace.client("solicit")[0]
    p = response(trace, "solicit")
    assert one(request, 14) == one(p, 14) == b""
    keys = installed(trace, p)
    assert {k[0] for k in keys} == set(trace.before["ia_kinds"])
    assert not any(q.name == "request" and q.index > request.index for q in trace.packets)
