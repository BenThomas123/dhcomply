from lease_checks import response, installed, offers


def check(trace):
    candidates, chosen = offers(trace)
    p = response(trace, "request")
    keys = installed(trace, p)
    assert trace.client("solicit")[0].index < chosen.index < trace.client("request")[0].index < p.index
