from lease_checks import duid, leases


def check(trace):
    p = trace.server("reply")[0]
    assert trace.before["outstanding_exchanges"] == [] and not any(q.sport == 546 and q.index < p.index for q in trace.packets)
    assert duid(p).hex() == trace.before["client_duid"]
    assert leases(trace.before) == leases(trace.after) and trace.before["dns_servers"] == trace.after["dns_servers"]
