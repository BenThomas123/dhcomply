import ipaddress
import struct

from validation_checks import associations, evidence, incoming


def check(trace):
    packet = incoming(trace, "reply")
    advertisements = trace.after["downstream_prefix_advertisements"]
    evidence(advertisements, "Capture downstream router advertisements after the upstream update")
    grants = {}
    for _, _, children in associations(packet, 25).values():
        for code, data in children:
            if code == 26 and len(data) >= 25:
                network = ipaddress.IPv6Network((data[9:25], data[8]), strict=False)
                grants[network] = struct.unpack_from("!II", data)
    for ad in advertisements:
        prefix = ipaddress.IPv6Network(ad["prefix"])
        candidates = [life for subnet, life in grants.items() if prefix.subnet_of(subnet)]
        evidence(len(candidates) == 1 and ad["time"] >= packet.time, "Need one matching delegated prefix")
        elapsed = int(ad["time"] - packet.time)
        for granted, emitted in zip(candidates[0], (ad["preferred"], ad["valid"])):
            assert emitted <= (granted if granted == 0xffffffff else max(0, granted - elapsed))
