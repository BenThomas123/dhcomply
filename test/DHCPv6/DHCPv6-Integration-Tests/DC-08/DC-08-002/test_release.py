from lease_checks import bindings, leases, preserved, no_use


def check(trace):
    p = trace.client("release")[0]
    previous = leases(trace.before)
    removed = set(bindings(p))
    assert {k[2] for k in removed} == set(trace.before["release_targets"])
    assert removed < previous.keys()
    no_use(trace, removed)
    preserved(trace, previous.keys() - removed)
