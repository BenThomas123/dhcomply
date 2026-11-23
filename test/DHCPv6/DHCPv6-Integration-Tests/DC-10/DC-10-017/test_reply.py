import ipaddress

from validation_checks import evidence, incoming


def check(trace):
    packet = incoming(trace, "reply")
    evidence(len(packet.options(12)) == 1 and len(packet.options(12)[0]) == 16,
             "Missing Server Unicast option")
    out = [p for p in trace.packets if p.sport == 546 and p.index > packet.index and p.iface == packet.iface]
    evidence(out, "Capture the following client transmission")
    assert ipaddress.IPv6Address(out[0].dst) == ipaddress.IPv6Address("ff02::1:2")
