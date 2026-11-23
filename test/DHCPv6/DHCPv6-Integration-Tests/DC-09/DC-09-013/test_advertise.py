from lease_checks import response, status


def check(trace):
    p = response(trace, "solicit", "advertise")
    assert status(p) == trace.before["injected_status"]
    later = [q for q in trace.packets if q.index > p.index and q.name == "request" and q.options(2) == p.options(2)]
    assert bool(later) == trace.before["offer_is_selectable"]
    assert trace.after["time"] >= p.time + trace.before["selection_window"]
