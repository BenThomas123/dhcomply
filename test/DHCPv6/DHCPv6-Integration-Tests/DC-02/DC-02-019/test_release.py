from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "release")
    rejected(trace, origin, packet)
