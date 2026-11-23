from lease_checks import leases, events, response, installed


def check(trace):
    p = response(trace, "rebind")
    previous = leases(trace.before)
    keys = installed(trace, p)
    added = {k for k in keys - previous.keys() if k[0] == "na"}
    assert added and keys & previous.keys()
    for k in added:
        done = [e for e in events(trace, "dad_complete") if e["resource"] == k[2] and e["time"] >= p.time]
        assert done and all(e["time"] >= done[0]["time"] for e in events(trace, "address_used") if e["resource"] == k[2])
