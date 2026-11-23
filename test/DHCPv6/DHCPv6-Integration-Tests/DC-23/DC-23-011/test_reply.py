from validation_checks import evidence, incoming, resources, unknown_option


def check(trace):
    packet = incoming(trace, "reply")
    code = trace.before["unsupported_option_code"]
    evidence(packet.options(code) == [b""] and packet.options(23) and resources(packet, 3),
             "Need an empty unknown option alongside DNS and an address")
    unknown_option(trace, packet)
