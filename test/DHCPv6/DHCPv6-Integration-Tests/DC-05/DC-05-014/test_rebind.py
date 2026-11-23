from lease_checks import bindings, leases, response, installed, preserved


def check(trace):
    p = response(trace, "rebind")
    records = bindings(p)
    previous = leases(trace.before)
    installed(trace, p)
    omitted = previous.keys() - records.keys()
    assert any(k[:2] in {a[:2] for a in records} for k in omitted)
    preserved(trace, omitted)
