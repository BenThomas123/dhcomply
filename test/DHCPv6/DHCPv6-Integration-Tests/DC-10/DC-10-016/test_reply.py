from validation_checks import evidence, incoming, instrumented, malformed


def check(trace):
    packet = incoming(trace, "reply")
    evidence(malformed(packet.raw[4:]) or any(len(v) < 12 for c in (3, 25) for v in packet.options(c)),
             "Missing malformed option evidence")
    instrumented(trace)
