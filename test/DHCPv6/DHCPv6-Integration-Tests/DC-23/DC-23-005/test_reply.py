from validation_checks import evidence, incoming, instrumented, tlvs, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    evidence(any(c == 26 and len(v) < 25 for ia in packet.options(25) for c, v in tlvs(ia[12:])), "Capture does not contain the target option defect")
    unchanged(trace)
    instrumented(trace)
