from timing_checks import EPS


def check(trace):
    first = trace.client("information_request")[0]
    assert 0 <= first.time - trace.before["start"] <= 1 + EPS
