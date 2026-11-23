from validation_checks import evidence, exchange


def check(trace):
    origin, packet = exchange(trace, "reply", "information_request")
    old = set(trace.before["dhcp_dns_servers"])
    evidence(old and not packet.options(23) and packet.xid == origin.xid, "Missing omission stimulus")
    assert old.isdisjoint(trace.after["dhcp_dns_servers"]), "Omitted DHCP DNS data was retained"
