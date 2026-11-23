from reconfigure_checks import rejected


def check(trace):
    rejected(trace, "missing_type")
