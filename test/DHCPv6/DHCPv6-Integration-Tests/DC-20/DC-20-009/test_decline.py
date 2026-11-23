from lease_checks import bindings, response, no_use, status, retry


def check(trace):
    p = response(trace, "decline")
    q = trace.client("decline")[0]
    assert status(p) == 3 and retry(trace, "decline", 2)[1].index < p.index
    assert trace.after["time"] - p.time >= trace.before["retry_window"] > 0
    assert not any(m.name == q.name and m.xid == q.xid and m.index > p.index for m in trace.packets)
    no_use(trace, set(bindings(q)))
