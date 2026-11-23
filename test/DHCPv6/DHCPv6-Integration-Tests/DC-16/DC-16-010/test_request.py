from lease_checks import response, installed


def check(trace):
    p = response(trace, "request")
    keys = installed(trace, p)
    assert {k[0] for k in keys if k[1] == 7} == {"na", "pd"}
