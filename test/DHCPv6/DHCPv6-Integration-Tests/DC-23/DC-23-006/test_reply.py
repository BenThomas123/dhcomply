from validation_checks import evidence, incoming, instrumented, malformed, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(any(len(v) >= 12 and malformed(v[12:]) for v in packet.options(3)), "Capture does not contain the target option defect")
    unchanged(trace)
    instrumented(trace)
