from reconfigure_checks import failed_refresh


def check(trace):
    failed_refresh(trace, "renew")
