from lease_checks import bindings, response, installed


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    keys = {k for k, (pref, valid) in records.items() if pref == 0 < valid}
    assert keys and keys <= installed(trace, p)
    assert all(k[2] in trace.after["deprecated"] for k in keys)
