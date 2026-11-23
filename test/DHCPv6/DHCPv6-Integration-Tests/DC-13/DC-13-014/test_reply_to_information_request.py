import ipaddress

from validation_checks import evidence, exchange


def check(trace):
    origin, packet = exchange(trace, "reply", "information_request")
    evidence(packet.xid == origin.xid and packet.options(23), "Missing correlated DNS Reply")
    assert not origin.options(3) and not origin.options(25)
    raw = b"".join(packet.options(23))
    evidence(len(raw) > 0 and len(raw) % 16 == 0, "Malformed DNS fixture")
    servers = {str(ipaddress.IPv6Address(raw[i:i+16])) for i in range(0, len(raw), 16)}
    assert servers <= set(trace.after["dns_servers"])
    assert trace.before["bound_iaids"] == trace.after["bound_iaids"] == []
