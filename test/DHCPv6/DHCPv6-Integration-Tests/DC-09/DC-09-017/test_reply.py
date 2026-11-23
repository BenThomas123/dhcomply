from lease_checks import leases


def check(trace):
    p = trace.server("reply")[0]
    assert any(len(data) < 2 for data in p.options(13))
    assert trace.after["client_alive"] and leases(trace.after) == leases(trace.before)
