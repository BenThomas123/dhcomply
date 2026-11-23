from lease_checks import offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    ranks = {preference(p) for p in candidates}
    assert len(ranks) >= 2
    assert preference(chosen) == max(ranks)
