from timing_checks import cap_value


def check(trace):
    cap_value(trace, "information_request", "reply", 86400)
