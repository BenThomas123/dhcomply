from validation_checks import evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "reply")
    ids = packet.options(2)
    evidence(len(ids) == 1 and len(ids[0]) == 131, "Wrong DUID length for this boundary")
    rejected(trace, origin, packet)
