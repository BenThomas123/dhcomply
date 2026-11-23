from lease_checks import duid, leases


def check(trace):
    req = trace.client("request")[0]
    bad = trace.server("reply")[-1]
    assert bad.index > req.index and bad.xid == req.xid and duid(bad, 2) != duid(req, 2)
    assert duid(bad) == duid(req)
    assert leases(trace.after) == leases(trace.before) and trace.after["server_duid"] != duid(bad, 2).hex()
