from lease_checks import bindings, leases, event, no_use


def check(trace):
    p = trace.client("solicit")[0]
    previous = leases(trace.before)
    expired = {k for k, r in previous.items() if r["valid_until"] <= event(trace, "reboot")["time"]}
    no_use(trace, expired)
    assert not set(bindings(p)).intersection(expired)
