from lease_checks import bindings, response, status


def check(trace):
    p = response(trace, "solicit")
    assert status(p) == 4
    followups = [q for q in trace.packets if q.index > p.index and q.name in ("solicit", "request")]
    assert followups and (followups[0].name == "solicit" or not bindings(followups[0]))
