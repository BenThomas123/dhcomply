from validation_checks import evidence, incoming, resources, unknown_option


def check(trace):
    packet = incoming(trace, "advertise")
    evidence(resources(packet, 3) or resources(packet, 25), "Expected valid lease resources")
    unknown_option(trace, packet)
