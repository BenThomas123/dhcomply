from lease_checks import bindings, leases, response, deadlines, no_use


def check(trace):
    p = response(trace, "renew")
    previous = leases(trace.before)
    records = bindings(p)
    withdrawals = {k for k, (_, valid) in records.items() if k[0] == "pd" and valid == 0 and k in previous}
    no_use(trace, withdrawals)
    deadlines(trace, p)
    assert any(k in previous and k[0] == "pd" and valid > 0 for k, (_, valid) in records.items())
