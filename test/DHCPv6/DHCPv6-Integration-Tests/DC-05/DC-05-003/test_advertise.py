from lease_checks import bindings


def check(trace):
    p = trace.server("advertise")[0]
    actual = {(i, r, pref, valid) for (k, i, r), (pref, valid) in bindings(p).items() if k == "na"}
    assert actual and actual == {tuple(row) for row in trace.before["wire_vectors"]}
