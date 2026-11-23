from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "request")
    rejected(trace, origin, packet)
