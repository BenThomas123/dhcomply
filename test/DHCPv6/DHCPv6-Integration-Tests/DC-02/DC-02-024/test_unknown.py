from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "unknown")
    rejected(trace, origin, packet)
