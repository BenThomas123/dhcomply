from lease_checks import bindings, leases, response, deadlines


def check(trace):
    p = response(trace, "renew")
    previous = leases(trace.before)
    records = bindings(p)
    assert any(k in previous and p.time + valid < previous[k]["valid_until"] for k, (_, valid) in records.items())
    deadlines(trace, p)
