from validation_checks import evidence, incoming, progressed


def check(trace):
    packet = incoming(trace, "reply")
    ids = packet.options(2)
    evidence(len(ids) == 1 and 3 <= len(ids[0]) <= 130 and
             int.from_bytes(ids[0][:2], "big") not in trace.before["known_duid_types"],
             "Need a valid opaque server DUID of an unsupported type")
    progressed(trace, packet)
