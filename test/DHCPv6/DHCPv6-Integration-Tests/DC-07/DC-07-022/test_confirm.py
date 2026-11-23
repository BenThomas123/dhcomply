from lease_checks import bindings, response


def check(trace):
    release = trace.client("release")[0]
    grant = response(trace, "request")
    confirm = trace.client("confirm")[-1]
    assert release.index < grant.index < confirm.index
    assert set(bindings(confirm)) and set(bindings(confirm)) <= set(bindings(grant))
