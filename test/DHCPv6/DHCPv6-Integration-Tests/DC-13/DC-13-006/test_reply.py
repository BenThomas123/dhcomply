from validation_checks import evidence, exchange, resources


def check(trace):
    origin, packet = exchange(trace, "reply")
    evidence(packet.xid == origin.xid and packet.options(1) == origin.options(1) and packet.options(2),
             "Reply must be correlated")
    evidence(not resources(packet, 3) and not resources(packet, 25), "Need a Reply without offered resources")
    assert not (set(trace.after["addresses"]) - set(trace.before["addresses"]))
    assert not (set(trace.after["prefixes"]) - set(trace.before["prefixes"]))
