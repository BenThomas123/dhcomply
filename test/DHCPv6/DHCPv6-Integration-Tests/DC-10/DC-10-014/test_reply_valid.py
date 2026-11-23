from validation_checks import check_nesting, evidence, incoming, progressed


def check(trace):
    packet = incoming(trace, "reply")
    evidence(packet.options(3) or packet.options(25), "Expected nested IA options")
    check_nesting(packet.raw[4:])
    progressed(trace, packet)
