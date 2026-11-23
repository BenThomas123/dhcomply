from timing_checks import cap_value


def check(trace):
    cap_value(trace, "solicit", "advertise+reply", "default")
