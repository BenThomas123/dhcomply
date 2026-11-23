from lease_checks import offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    ranks = {preference(p) for p in candidates}
    assert any(not p.options(7) for p in candidates) and any(p.options(7) == [bytes([0])] for p in candidates)
    assert preference(chosen) == max(ranks)
