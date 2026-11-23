from lease_checks import bindings, response, no_use


def check(trace):
    p = response(trace, "release")
    assert not p.options(13)
    no_use(trace, set(bindings(trace.client("release")[0])))
