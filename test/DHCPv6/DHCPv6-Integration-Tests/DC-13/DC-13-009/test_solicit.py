from validation_checks import evidence, resources


def check(trace):
    expired = set(trace.before["abandoned_resources"])
    evidence(expired, "Missing expired DHCP resources")
    for packet in trace.client("solicit"):
        assert expired.isdisjoint(resources(packet, 3) | resources(packet, 25))
