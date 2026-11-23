from lease_checks import bindings, response, no_use, status


def check(trace):
    ack = response(trace, "confirm")
    release = trace.client("release")[-1]
    assert status(ack) == 0 and ack.index < release.index
    no_use(trace, set(bindings(release)))
