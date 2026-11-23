from timing_checks import duration_limit, unchanged_leases


def check(trace):
    duration_limit(trace, "confirm")
    unchanged_leases(trace)
