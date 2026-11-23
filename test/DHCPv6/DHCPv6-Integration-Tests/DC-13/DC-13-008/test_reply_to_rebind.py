from validation_checks import associations, evidence, exchange


def check(trace):
    origin, packet = exchange(trace, "reply", "rebind")
    lost = set()
    valid = set()
    for kind in (3, 25):
        for iaid, (_, _, children) in associations(packet, kind).items():
            if any(code == 13 and data[:2] == bytes([0, 3]) for code, data in children):
                lost.add(iaid)
            elif any(code in (5, 26) for code, _ in children):
                valid.add(iaid)
    evidence(lost and valid and packet.xid == origin.xid, "Expected NoBinding and updated leases in one Reply")
    assert valid <= set(trace.after["bound_iaids"])
