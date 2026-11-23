from validation_checks import associations, evidence, incoming


def check(trace):
    packet = incoming(trace, "reply")
    infinite = set()
    for kind in (3, 25):
        for iaid, (_, _, children) in associations(packet, kind).items():
            for code, value in children:
                offset = 20 if code == 5 else 4
                if code in (5, 26) and value[offset:offset + 4] == bytes([255]) * 4:
                    infinite.add(iaid)
    evidence(infinite and trace.before["clock_seconds"] // 2**32 < trace.after["clock_seconds"] // 2**32,
             "Need an infinite binding and an observed timestamp wrap")
    assert infinite <= set(trace.after["bound_iaids"])
