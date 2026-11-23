from lease_checks import leases, response, installed, preserved


def check(trace):
    p = response(trace, "renew")
    previous = leases(trace.before)
    for kind in ("na", "pd"):
        assert len({i for k, i, _ in previous if k == kind}) >= 2
    updated = installed(trace, p)
    assert len({key[:2] for key in updated}) == 1
    preserved(trace, previous.keys() - updated)
