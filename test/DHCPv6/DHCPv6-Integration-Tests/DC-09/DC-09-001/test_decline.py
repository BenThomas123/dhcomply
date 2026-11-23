from lease_checks import bindings, response, no_use, status


def check(trace):
    p = response(trace, "decline")
    assert status(p) == 0
    no_use(trace, set(bindings(trace.client("decline")[0])))
