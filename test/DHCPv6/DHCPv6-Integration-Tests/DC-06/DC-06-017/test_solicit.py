from lease_checks import timed, retry


def check(trace):
    first, second = retry(trace, "solicit", 2)[:2]
    assert any(first.index < p.index < second.index for p in trace.server("advertise"))
    timed(trace, second.time, first.time + trace.before["first_rt"])
