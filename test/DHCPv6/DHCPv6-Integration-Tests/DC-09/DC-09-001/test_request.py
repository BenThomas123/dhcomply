from lease_checks import response, installed, status


def check(trace):
    p = response(trace, "request")
    assert status(p) == 0
    installed(trace, p)
