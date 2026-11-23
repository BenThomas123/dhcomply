from validation_checks import evidence, exchange, progressed


def check(trace):
    origin, packet = exchange(trace, "reply")
    ids = packet.options(2)
    evidence(len(ids) == 1 and len(ids[0]) == 130, "Wrong DUID length for this boundary")
    progressed(trace, packet)
