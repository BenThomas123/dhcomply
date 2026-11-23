from lease_checks import event


def check(trace):
    marker = event(trace, "on_link_prefix_change")
    packets = [p for p in trace.client("rebind") if p.time >= marker["time"]]
    assert packets and trace.before["minimum_refresh_interval"] > 0
    assert all(b.time - a.time >= trace.before["minimum_refresh_interval"] for a, b in zip(packets, packets[1:]))
