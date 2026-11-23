from lease_checks import bindings, no_use, retry


def check(trace):
    packets = retry(trace, "release", 2)
    assert len(packets) == trace.before["release_transmission_limit"]
    assert trace.after["time"] - packets[-1].time >= trace.before["retry_window"]
    assert not any(q.name == "reply" and q.xid == packets[0].xid for q in trace.packets)
    no_use(trace, set(bindings(packets[0])))
