from timing_checks import cap_value


def check(trace):
    cap_value(trace, "solicit", "reply", 86401)
