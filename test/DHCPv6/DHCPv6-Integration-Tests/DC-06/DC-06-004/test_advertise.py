from lease_checks import offers


def check(trace):
    candidates, chosen = offers(trace)
    assert len(candidates) == 1
