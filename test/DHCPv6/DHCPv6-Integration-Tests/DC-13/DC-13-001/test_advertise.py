from validation_checks import evidence, exchange


def check(trace):
    origin, packet = exchange(trace, "advertise", "solicit")
    evidence(origin.xid != packet.xid and packet.time > origin.time, "Invalid Advertise must arrive mid-interval")
    retries = [p for p in trace.client("solicit") if p.index > packet.index and p.xid == origin.xid]
    control_interval = trace.before["control_retry_interval"]
    tolerance = trace.before["clock_tolerance"]
    evidence(0 <= tolerance < packet.time - origin.time < control_interval, "Need a discriminating control timing")
    assert retries and abs(retries[0].time - origin.time - control_interval) <= tolerance
