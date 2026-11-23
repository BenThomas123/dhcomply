from validation_checks import evidence, incoming, instrumented, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(any(len(v) < 12 for v in packet.options(25)), "Capture does not contain the target option defect")
    unchanged(trace)
    instrumented(trace)
