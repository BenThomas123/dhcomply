from lease_checks import duid, offers


def check(trace):
    candidates, chosen = offers(trace)
    requests = trace.client("request")
    assert len(requests) >= 2 and duid(requests[0], 2) != duid(requests[-1], 2)
    assert duid(requests[-1], 2) in {duid(p, 2) for p in candidates}
    assert not any(p.name == "reply" and p.xid == requests[0].xid for p in trace.packets)
