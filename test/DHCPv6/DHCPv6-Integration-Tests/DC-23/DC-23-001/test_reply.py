from validation_checks import evidence, incoming, instrumented, malformed, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(malformed(packet.raw[4:]), "Capture does not contain the target option defect")
    unchanged(trace)
    instrumented(trace)
