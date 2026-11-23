from lease_checks import leases, retry


def check(trace):
    packets = retry(trace, "solicit", 2)
    assert not any(p.name == "request" for p in trace.packets)
    assert not leases(trace.after)
