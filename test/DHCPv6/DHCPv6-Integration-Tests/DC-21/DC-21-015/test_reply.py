from resolver_checks import revoked


def check(trace):
    revoked(trace, "renew", 23)
