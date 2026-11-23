from lease_checks import bindings, response, installed


def check(trace):
    p = response(trace, "request")
    keys = installed(trace, p)
    hints = {k[2] for k in bindings(trace.client("solicit")[0]) if k[0] == "na"}
    assert hints and any(k[0] == "na" and k[2] not in hints for k in keys)
