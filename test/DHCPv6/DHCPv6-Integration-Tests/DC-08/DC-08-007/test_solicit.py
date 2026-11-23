from lease_checks import bindings, leases, response, installed


def check(trace):
    q = trace.client("release")[0]
    grant = response(trace, "request")
    assert q.index < trace.client("solicit")[-1].index < grant.index
    assert not (set(bindings(q)) - installed(trace, grant)) & leases(trace.after).keys()
