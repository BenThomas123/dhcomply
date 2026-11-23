from lease_checks import bindings, leases, response, no_use


def check(trace):
    p = response(trace, "renew")
    records = bindings(p)
    previous = leases(trace.before)
    no_use(trace, {k for k, (_, valid) in records.items() if valid == 0 and k in previous})
