from validation_checks import bad_checksum, evidence, incoming, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    bad_checksum(trace, packet)
    evidence(trace.before["udp_checksum_counter_isolated"], "Checksum counters must be isolated")
    assert trace.after["udp6_checksum_errors"] > trace.before["udp6_checksum_errors"], "No kernel checksum drop"
    unchanged(trace)
