def check(trace):
    upstream, downstream = trace.before["upstream"], trace.before["downstream"]
    assert upstream != downstream
    requests = [p for p in trace.client("solicit") if p.options(25)]
    assert requests and all(p.iface == upstream for p in requests)
