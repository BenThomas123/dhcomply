from validation_checks import bare_control, evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "reply", "information_request")
    bare_control(trace, origin, packet, 1, altered_xid=False)
    evidence(not origin.options(1) and packet.options(1), "Wrong stimulus for this identifier case")
    rejected(trace, origin, packet)
