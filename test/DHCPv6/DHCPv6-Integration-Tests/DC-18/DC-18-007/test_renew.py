from lease_checks import bindings, leases, response, deadlines


def check(trace):
    p = response(trace, "renew")
    records = bindings(p)
    previous = leases(trace.before)
    assert any(k[0] == "pd" and k in previous and p.time + valid < previous[k]["valid_until"] for k, (_, valid) in records.items())
    assert any(k[0] == "pd" and k not in previous for k in records)
    deadlines(trace, p)
