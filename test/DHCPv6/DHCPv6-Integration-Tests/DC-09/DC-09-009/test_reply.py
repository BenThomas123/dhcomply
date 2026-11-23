from lease_checks import one, response, installed, status


def check(trace):
    p = trace.server("reply")[0]
    assert status(p) == trace.before["unassigned_status_code"] > 6
    one(p, 13)[2:].decode("utf-8")
    assert trace.after["client_alive"]
    installed(trace, response(trace, "request"))
