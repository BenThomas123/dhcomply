from timing_checks import EPS, exchange, require


def check(trace):
    sends = exchange(trace, "solicit", 2)
    require(not sends[0].options(14), "normal Advertise collection required")
    assert 1 < sends[1].time - sends[0].time <= 1.1 + EPS
