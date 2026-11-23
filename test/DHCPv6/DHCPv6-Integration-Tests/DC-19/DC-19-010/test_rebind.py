from lease_checks import event


def check(trace):
    e = event(trace, "unrelated_change")
    assert trace.before["link_local"] == trace.after["link_local"] and trace.after["time"] < min(r["renew_at"] for r in trace.before["timers"])
    assert trace.after["time"] > e["time"] and not any(q.name == "rebind" and q.time >= e["time"] for q in trace.packets)
