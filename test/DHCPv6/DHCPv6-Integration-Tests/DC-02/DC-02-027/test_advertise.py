from validation_checks import evidence, incoming, instrumented, malformed, unchanged


def check(trace):
    packet = incoming(trace, "advertise")
    evidence(malformed(packet.raw[4:]), "Missing invalid TLV length")
    instrumented(trace)
    unchanged(trace)
