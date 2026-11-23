from lease_checks import duid, response, installed


def check(trace):
    p = response(trace, "rebind")
    server = duid(p, 2).hex()
    assert server != trace.before["server_duid"] and trace.after["server_duid"] == server
    installed(trace, p)
