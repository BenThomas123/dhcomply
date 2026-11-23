from lease_checks import associations, bindings, leases, response


def check(trace):
    p = response(trace, "request")
    bad = {(k, i) for k, i, t1, t2, _ in associations(p) if k == "na" and t1 > t2 > 0}
    assert bad and not any(k[:2] in bad for k in leases(trace.after))
    prefixes = {k for k in bindings(p) if k[0] == "pd"}
    assert prefixes and prefixes <= leases(trace.after).keys()
