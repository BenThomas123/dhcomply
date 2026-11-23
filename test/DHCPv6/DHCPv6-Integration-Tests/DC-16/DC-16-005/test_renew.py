from lease_checks import bindings, leases, response, deadlines, preserved


def check(trace):
    p = response(trace, "renew")
    previous = leases(trace.before)
    records = bindings(p)
    omitted = {k for k in previous if k[0] == "na" and k not in records}
    assert omitted and any(k[0] == "na" for k in records)
    assert any((k[:2] in {j[:2] for j in records}) == False for k in omitted)
    deadlines(trace, p)
    preserved(trace, omitted)
