from validation_checks import bare_control, evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "reply", "release")
    bare_control(trace, origin, packet, 1, altered_xid=False)
    evidence(packet.options(1) and origin.options(1) and packet.options(1) != origin.options(1), "Wrong stimulus for this identifier case")
    evidence((len(origin.options(1)[0]) == len(packet.options(1)[0])) == True, "Unexpected identifier length variant")
    rejected(trace, origin, packet)
