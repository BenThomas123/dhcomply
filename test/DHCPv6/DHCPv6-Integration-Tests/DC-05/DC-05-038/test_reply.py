from lease_checks import bindings, events


def check(trace):
    p = trace.server("reply")[0]
    prefixes = {k[2]: times for k, times in bindings(p).items() if k[0] == "pd"}
    adverts = events(trace, "downstream_ra")
    assert adverts and prefixes
    for e in adverts:
        assert e["time"] >= p.time and e["delegated"] in prefixes
        preferred, valid = prefixes[e["delegated"]]
        age = e["time"] - p.time
        assert e["preferred"] <= max(0, preferred - age) and e["valid"] <= max(0, valid - age)
