from resolver_checks import oro


def check(trace):
    p = trace.client("information_request")[0]
    assert (32 in oro(p)) == True
