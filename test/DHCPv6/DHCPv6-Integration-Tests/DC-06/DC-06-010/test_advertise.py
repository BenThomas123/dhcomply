from lease_checks import duid, offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    ranks = {preference(p) for p in candidates}
    assert len(ranks) == 1 and len({duid(p, 2) for p in candidates}) >= 2
    assert preference(chosen) == max(ranks)
