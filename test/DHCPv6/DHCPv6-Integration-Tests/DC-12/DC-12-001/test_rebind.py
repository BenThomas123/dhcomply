from timing_checks import require


def check(trace):
    require(trace.before["reconfigure_accept"] is False, "disable Reconfigure acceptance")
    assert all(not p.options(20) for p in trace.client("rebind"))
