from lease_checks import associations


def check(trace):
    p = trace.client("solicit")[0]
    for kind in trace.before["configured_ia_counts"]:
        ids = [i for k, i, *_ in associations(p) if k == kind]
        assert len(ids) == trace.before["configured_ia_counts"][kind] >= 2
        assert len(set(ids)) == len(ids)
    assert trace.before["configured_ia_counts"]
