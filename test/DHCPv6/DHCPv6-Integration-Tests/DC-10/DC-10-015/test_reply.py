from validation_checks import incoming, unknown_option


def check(trace):
    packet = incoming(trace, "reply")
    unknown_option(trace, packet)
