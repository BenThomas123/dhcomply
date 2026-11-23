from lease_checks import bindings, timed, retry


def check(trace):
    first, second = retry(trace, "solicit", 2)[:2]
    p = trace.server("advertise")[0]
    assert not bindings(p) and first.index < p.index < second.index
    timed(trace, second.time, first.time + trace.before["first_rt"])
