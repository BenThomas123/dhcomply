from lease_checks import associations, response, deadlines, timed


def check(trace):
    p = response(trace, "renew")
    deadlines(trace, p)
    rows = {(r["kind"], r["iaid"]): r for r in trace.after["timers"]}
    for kind, iaid, t1, t2, _ in associations(p):
        timed(trace, rows[kind, iaid]["renew_at"], p.time + t1)
        timed(trace, rows[kind, iaid]["rebind_at"], p.time + t2)
