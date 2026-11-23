from validation_checks import evidence, incoming, instrumented, tlvs, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(any(c == 5 and len(v) < 24 for ia in packet.options(3) for c, v in tlvs(ia[12:])), "Capture does not contain the target option defect")
    unchanged(trace)
    instrumented(trace)
