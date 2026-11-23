from lease_checks import status


def check(trace):
    p = trace.server("reply")[0]
    assert status(p) == 5
    followups = [q for q in trace.packets if q.index > p.index and q.sport == 546]
    assert followups and all(q.dst == "ff02::1:2" for q in followups)
