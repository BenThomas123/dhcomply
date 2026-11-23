from lease_checks import associations


def check(trace):
    p = trace.client("decline")[0]
    ias = [(i, t1, t2) for k, i, t1, t2, _ in associations(p) if k == "na"]
    assert ias and len(ias) == len({row[0] for row in ias})
    assert {row[0] for row in ias} == set(trace.before["configured_iaids"]["na"])
