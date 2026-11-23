from validation_checks import associations, evidence, incoming


def check(trace):
    packet = incoming(trace, "reply")
    timers = [e[1] for kind in (3, 25) for e in associations(packet, kind).values()]
    evidence(timers and not any(timers), "Fixture must use zero timers")
    later = [p for p in trace.client("rebind") if p.index > packet.index and p.iface == packet.iface]
    assert later and later[0].time - packet.time >= trace.before["minimum_safe_interval"] > 0
