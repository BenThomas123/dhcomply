from lease_checks import bindings, response, installed


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    keys = installed(trace, p)
    assert any(0 < pref == valid and k in keys for k, (pref, valid) in records.items())
