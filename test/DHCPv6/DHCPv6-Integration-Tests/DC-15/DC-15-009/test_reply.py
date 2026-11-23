from lease_checks import response, deadlines


def check(trace):
    p = response(trace, "renew")
    unknown = trace.before["unknown_option_code"]
    assert p.options(unknown)
    deadlines(trace, p)
