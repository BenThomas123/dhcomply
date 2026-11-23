from validation_checks import associations, evidence


def check(trace):
    expected = set(trace.before["configured_iaids"])
    evidence(len(expected) >= 2, "Configure at least two distinct IAs")
    for packet in trace.client("release"):
        assert expected.issubset(associations(packet, 25)), "Missing distinct IAID"
