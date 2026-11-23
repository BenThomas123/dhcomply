from validation_checks import bad_checksum, incoming, unchanged


def check(trace):
    packet = incoming(trace, "advertise")
    bad_checksum(trace, packet)
    unchanged(trace)
