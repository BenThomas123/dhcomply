from validation_checks import evidence, oro


def check(trace):
    expected = set(trace.before["requested_option_codes"])
    evidence(len(expected) >= 2, "Configure multiple requested options")
    for packet in trace.client("information_request"):
        assert expected.issubset(oro(packet)), "Requested code lost or byte-swapped"
