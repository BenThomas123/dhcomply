from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "relay_forward")
    rejected(trace, origin, packet)
