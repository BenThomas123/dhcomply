from lease_checks import bindings, no_use, status


def check(trace):
    p = trace.server("reply")[0]
    assert status(p) == 1
    invalid = {k for k, (pref, valid) in bindings(p).items() if pref > valid or not valid}
    no_use(trace, invalid)
