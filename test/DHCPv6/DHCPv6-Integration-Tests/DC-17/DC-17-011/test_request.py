from timing_checks import number, require


def check(trace):
    old = trace.client("solicit")[-1]
    new = trace.client("request")[0]
    require(old.index < new.index and number(old, 8, 2) > 0, "capture a long discovery phase")
    assert number(new, 8, 2) == 0
