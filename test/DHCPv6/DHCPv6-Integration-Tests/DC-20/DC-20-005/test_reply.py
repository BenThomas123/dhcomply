from lease_checks import bindings, leases, events, response


def check(trace):
    p = response(trace, "request")
    new = {k[2] for k in bindings(p) if k[0] == "na" and k not in leases(trace.before)}
    assert new
    for addr in new:
        done = [e["time"] for e in events(trace, "dad_complete") if e["resource"] == addr]
        uses = [e["time"] for e in events(trace, "address_used") if e["resource"] == addr]
        assert done and min(done) > p.time and uses and min(uses) >= min(done)
