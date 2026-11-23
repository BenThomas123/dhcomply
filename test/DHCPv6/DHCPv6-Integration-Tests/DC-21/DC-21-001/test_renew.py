from resolver_checks import oro


def check(trace):
    p = trace.client("renew")[0]
    assert (32 in oro(p)) == False
