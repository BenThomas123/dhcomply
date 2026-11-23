from lease_checks import bindings, leases, response, deadlines


def check(trace):
    p = response(trace, "renew")
    previous = leases(trace.before)
    records = bindings(p)
    assert any(key in previous and previous[key]["valid_until"] != p.time + v for key, (_, v) in records.items())
    deadlines(trace, p)
