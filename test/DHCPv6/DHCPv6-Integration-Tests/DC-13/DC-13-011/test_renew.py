from validation_checks import associations, evidence, incoming


def check(trace):
    packet = incoming(trace, "reply")
    timers = [entry[0] for kind in (3, 25) for entry in associations(packet, kind).values()]
    evidence(len(timers) >= 3 and len(set(timers)) >= 2 and min(timers) > 0, "Need three nonzero IA deadlines")
    later = [p for p in trace.client("renew") if p.index > packet.index and p.iface == packet.iface]
    assert later and later[0].time <= packet.time + min(timers) + trace.before["clock_tolerance"]
