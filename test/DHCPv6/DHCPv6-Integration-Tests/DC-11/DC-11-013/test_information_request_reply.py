from resolver_checks import revoked


def check(trace):
    revoked(trace, "information_request", 24)
