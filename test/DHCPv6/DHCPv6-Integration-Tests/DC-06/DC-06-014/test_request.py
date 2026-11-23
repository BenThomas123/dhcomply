from lease_checks import duid, offers


def check(trace):
    candidates, chosen = offers(trace)
    assert duid(trace.client("request")[0], 2) == duid(chosen, 2)
