from lease_checks import one, response, installed, offers


def check(trace):
    candidates, chosen = offers(trace)
    assert one(trace.client("solicit")[0], 14) == b""
    installed(trace, response(trace, "request"))
