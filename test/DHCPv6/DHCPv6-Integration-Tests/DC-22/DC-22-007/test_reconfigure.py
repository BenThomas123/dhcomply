from reconfigure_checks import rejected


def check(trace):
    rejected(trace, "bad_mac")
