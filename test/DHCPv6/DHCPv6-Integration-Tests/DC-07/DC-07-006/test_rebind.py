from lease_checks import timed


def check(trace):
    p = trace.client("rebind")[0]
    timers = trace.before["timers"]
    assert timers
    timed(trace, p.time, min(row["rebind_at"] for row in timers))
    renew = trace.client("renew")[0]
    assert renew.index < p.index and not any(q.name == "reply" and renew.index < q.index < p.index for q in trace.packets)
