from validation_checks import evidence, incoming, instrumented, unchanged


def check(trace):
    packet = incoming(trace, "reconfigure")
    evidence(0 < len(packet.raw) < 4, "Missing required truncation variant")
    instrumented(trace)
    unchanged(trace)
