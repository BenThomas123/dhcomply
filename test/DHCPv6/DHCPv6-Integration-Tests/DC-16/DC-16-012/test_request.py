from lease_checks import bindings, response, installed, no_use


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    bad = {k for k, (a, b) in records.items() if k[0] == "na" and a > b}
    no_use(trace, bad)
    assert any(k[0] == "na" for k in installed(trace, p))
