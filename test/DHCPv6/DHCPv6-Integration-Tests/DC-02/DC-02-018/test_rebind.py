from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "rebind")
    rejected(trace, origin, packet)
