from validation_checks import incoming, unknown_option


def check(trace):
    packet = incoming(trace, "advertise")
    unknown_option(trace, packet)
