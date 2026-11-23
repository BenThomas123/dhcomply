from validation_checks import bare_control, evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "reply", "request")
    bare_control(trace, origin, packet, 2, altered_xid=False)
    evidence(not packet.options(2), "Wrong stimulus for this identifier case")
    rejected(trace, origin, packet)
