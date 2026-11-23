from validation_checks import evidence, incoming, instrumented, malformed, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(malformed(packet.raw[4:]) and len(packet.raw) - trace.before["truncation_offset"] >= 4, "Missing required truncation variant")
    instrumented(trace)
    unchanged(trace)
