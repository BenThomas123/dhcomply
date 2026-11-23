from lease_checks import associations, leases


def check(trace):
    p = trace.server("reply")[0]
    options = [v for k, _, _, _, nested in associations(p) if k == "pd" for c, v in nested if c == 26]
    assert any(len(v) >= 25 and v[8] == 0 and any(v[9:25]) for v in options)
    assert trace.after["client_alive"]
    assert leases(trace.after) == leases(trace.before)
