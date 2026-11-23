from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "confirm")
    rejected(trace, origin, packet)
