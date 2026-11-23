from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "relay_reply")
    rejected(trace, origin, packet)
