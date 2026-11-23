from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "decline")
    rejected(trace, origin, packet)
