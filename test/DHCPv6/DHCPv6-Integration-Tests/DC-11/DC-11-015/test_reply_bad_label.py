from resolver_checks import invalid_resolver


def check(trace):
    invalid_resolver(trace, "information_request", 24, "bad_label")
