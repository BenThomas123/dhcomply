from lease_checks import bindings, leases


def check(trace):
    p = trace.client("renew")[0]
    previous = leases(trace.before)
    prefixes = {k for k in previous if k[0] == "pd"}
    assert prefixes and prefixes <= bindings(p).keys()
