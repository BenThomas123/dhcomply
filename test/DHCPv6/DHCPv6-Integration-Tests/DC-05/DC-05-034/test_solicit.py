from lease_checks import bindings


def check(trace):
    p = trace.client("solicit")[0]
    hints = set(trace.before["resource_hints"])
    assert hints and hints == {k[2] for k in bindings(p)}
