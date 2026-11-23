from lease_checks import event


def check(trace):
    p = trace.client("renew")[0]
    e = event(trace, "link_local_changed")
    assert e["old"] != e["new"] == p.src and e["time"] <= p.time < min(r["renew_at"] for r in trace.before["timers"])
    assert trace.before["reconfigure_accept"]
