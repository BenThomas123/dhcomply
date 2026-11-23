from ipaddress import IPv6Network

from lease_checks import bindings, events


def check(trace):
    p = trace.server("reply")[0]
    prefixes = {k[2]: times for k, times in bindings(p).items() if k[0] == "pd"}
    adverts = events(trace, "downstream_ra")
    assert adverts and prefixes
    assert p.iface == trace.before["upstream"] != trace.before["downstream"]
    assert any(e["time"] >= p.time + 30 for e in adverts)
    for e in adverts:
        assert e["time"] >= p.time and e["delegated"] in prefixes
        subnet = IPv6Network(e["subnet"])
        delegation = IPv6Network(e["delegated"])
        assert e["iface"] == trace.before["downstream"] and subnet.subnet_of(delegation)
        assert delegation.prefixlen == 56 and subnet.prefixlen == 64
        preferred, valid = prefixes[e["delegated"]]
        age = e["time"] - p.time
        assert e["preferred"] <= max(0, preferred - age) and e["valid"] <= max(0, valid - age)
