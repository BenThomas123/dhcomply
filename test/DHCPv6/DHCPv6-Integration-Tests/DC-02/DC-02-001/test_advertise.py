from validation_checks import bare_control, evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "advertise", "solicit")
    bare_control(trace, origin, packet, None, altered_xid=True)
    evidence((packet.xid ^ origin.xid).bit_count() == 1, "Wrong stimulus for this identifier case")
    rejected(trace, origin, packet)
