from lease_checks import bindings, leases, no_use


def check(trace):
    p = trace.server("reply")[0]
    records = bindings(p)
    now = trace.after["time"]
    expired = {k for k, (_, valid) in records.items() if p.time + valid <= now}
    live = records.keys() - expired
    no_use(trace, expired)
    assert live and live <= leases(trace.after).keys()
    assert {k[:2] for k in expired}.isdisjoint({k[:2] for k in live})
