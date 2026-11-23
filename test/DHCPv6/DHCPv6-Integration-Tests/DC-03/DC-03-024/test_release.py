from timing_checks import count_limit, unchanged_leases


def check(trace):
    count_limit(trace, "release")
    unchanged_leases(trace)
