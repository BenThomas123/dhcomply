def check(trace):
    p = trace.client("information_request")[0]
    bad = trace.server("reply")[0]
    assert not p.options(1) and bad.options(1) and p.xid == bad.xid and bad.index > p.index
    assert trace.after["dns_servers"] == trace.before["dns_servers"] != trace.before["offered_dns_servers"]
