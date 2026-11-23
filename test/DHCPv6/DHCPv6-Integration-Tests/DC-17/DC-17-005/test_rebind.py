from lease_clock_checks import expiry


def check(trace):
    expiry(trace, "last")
