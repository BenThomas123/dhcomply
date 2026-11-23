from lease_checks import response, installed


def check(trace):
    p = response(trace, "solicit")
    assert not p.options(13)
    installed(trace, p)
