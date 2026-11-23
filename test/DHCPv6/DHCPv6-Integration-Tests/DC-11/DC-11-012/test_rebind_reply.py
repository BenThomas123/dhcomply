from resolver_checks import revoked


def check(trace):
    revoked(trace, "rebind", 23)
