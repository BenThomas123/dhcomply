from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "solicit")
    rejected(trace, origin, packet)
