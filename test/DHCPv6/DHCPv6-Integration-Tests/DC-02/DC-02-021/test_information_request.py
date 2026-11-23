from validation_checks import exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "information_request")
    rejected(trace, origin, packet)
