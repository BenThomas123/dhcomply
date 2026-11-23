from reconfigure_checks import duplicate


def check(trace):
    duplicate(trace, stale=True)
