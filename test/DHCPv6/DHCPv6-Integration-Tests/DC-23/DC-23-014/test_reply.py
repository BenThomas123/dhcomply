from validation_checks import evidence, incoming, resources


def check(trace):
    packet = incoming(trace, "reply")
    address = "2001:db8:1234::5"
    evidence(address in resources(packet, 3) and not trace.before["ra_onlink_prefixes"],
             "Case needs the assigned address and no on-link RA")
    assert address in trace.after["addresses"], "IA address was not configured"
    assert not any(r["destination"] == "2001:db8:1234::/64" and r["interface"] == packet.iface
                   and r["scope"] == "link" for r in trace.after["routes"])
