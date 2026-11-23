from validation_checks import bad_checksum, incoming, unchanged


def check(trace):
    packet = incoming(trace, "reconfigure")
    bad_checksum(trace, packet)
    unchanged(trace)
