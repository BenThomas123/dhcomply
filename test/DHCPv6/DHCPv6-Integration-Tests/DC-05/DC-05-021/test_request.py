from lease_checks import bindings, response, no_use


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    no_use(trace, {k for k, (pref, valid) in records.items() if pref > 0 == valid})
