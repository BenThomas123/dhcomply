from timing_checks import count_limit, unchanged_leases


def check(trace):
    count_limit(trace, "request")
    unchanged_leases(trace)
