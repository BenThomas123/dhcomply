from lease_checks import event, response, installed


def check(trace):
    p = response(trace, "request")
    assert event(trace, "link_change")["time"] < p.time
    installed(trace, p)
    for field in ("routes", "dns_servers", "prefixes"):
        stale = set(trace.before[field]) - set(trace.before["new_link_configuration"][field])
        assert not stale.intersection(trace.after[field])
