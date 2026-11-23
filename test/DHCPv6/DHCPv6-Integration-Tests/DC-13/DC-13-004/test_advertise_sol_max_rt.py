from validation_checks import caps, evidence, incoming


def check(trace):
    packet = incoming(trace, "advertise")
    statuses = packet.options(13)
    evidence(any(len(s) >= 2 and int.from_bytes(s[:2], "big") != 0 for s in statuses), "Failure status is required")
    value = caps(packet, 82)
    evidence(value != trace.before["effective_cap_seconds"], "Expected changed cap")
    assert trace.after["effective_cap_seconds"] == value
