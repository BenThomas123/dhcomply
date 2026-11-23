from lease_checks import bindings, response, no_use, status, retry


def check(trace):
    p = response(trace, "release")
    q = trace.client("release")[0]
    assert status(p) == 3 and retry(trace, "release", 2)[1].index < p.index
    assert trace.after["time"] - p.time >= trace.before["retry_window"] > 0
    assert not any(m.name == q.name and m.xid == q.xid and m.index > p.index for m in trace.packets)
    no_use(trace, set(bindings(q)))
