from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "renew")
    rejected(trace, origin, packet)
