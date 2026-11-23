from timing_checks import schedule


def check(trace):
    schedule(trace, "request", "jitter")
