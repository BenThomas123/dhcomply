from lease_checks import leases, preserved, first_after


def check(trace):
    p = first_after(trace, "reboot", "confirm")
    assert trace.after["time"] > p.time > trace.before["time"]
    preserved(trace, {k for k in leases(trace.before) if k[0] == "na"})
