from lease_checks import bindings, leases, response, no_use


def check(trace):
    p = response(trace, "rebind")
    records = bindings(p)
    previous = leases(trace.before)
    no_use(trace, {k for k, times in records.items() if times == (0, 0) and k in previous})
