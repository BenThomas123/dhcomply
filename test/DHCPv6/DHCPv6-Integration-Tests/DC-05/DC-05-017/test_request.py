from lease_checks import bindings, response, installed, no_use


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    invalid = {k for k, (pref, valid) in records.items() if pref > valid}
    no_use(trace, invalid)
    assert installed(trace, p)
