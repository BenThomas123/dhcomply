from lease_checks import timed


def check(trace):
    p = trace.client("renew")[0]
    timers = trace.before["timers"]
    assert timers
    timed(trace, p.time, min(row["renew_at"] for row in timers))
