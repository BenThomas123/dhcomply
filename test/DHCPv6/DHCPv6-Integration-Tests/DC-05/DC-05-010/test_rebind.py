from lease_checks import associations, response, timed


def check(trace):
    p = response(trace, "rebind")
    timers = {(r["kind"], r["iaid"]): r for r in trace.after["timers"]}
    ias = associations(p)
    assert ias
    for kind, iaid, t1, t2, _ in ias:
        assert 0 < t1 < t2
        timed(trace, timers[kind, iaid]["renew_at"], p.time + t1)
        timed(trace, timers[kind, iaid]["rebind_at"], p.time + t2)
