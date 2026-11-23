from resolver_checks import updated


def check(trace):
    updated(trace, "request", 23, "multiple")
