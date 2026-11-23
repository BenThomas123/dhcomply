from lease_checks import leases, preserved


def check(trace):
    p = trace.client("confirm")[0]
    assert trace.after["time"] >= p.time + trace.before["confirm_timeout"]
    assert not any(q.name == "reply" and q.xid == p.xid for q in trace.packets)
    previous = {k for k, r in leases(trace.before).items() if r["valid_until"] > trace.after["time"]}
    preserved(trace, previous)
