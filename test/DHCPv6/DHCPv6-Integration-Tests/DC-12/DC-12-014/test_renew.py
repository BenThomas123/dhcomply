from reconfigure_checks import triggered


def check(trace):
    triggered(trace, "renew")
