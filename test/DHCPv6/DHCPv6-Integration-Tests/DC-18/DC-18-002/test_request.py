from lease_checks import bindings, response, installed


def check(trace):
    p = response(trace, "request")
    assert any(k[0] == "pd" and k[2] == "::/56" for k in bindings(trace.client("solicit")[0]))
    assert any(k[0] == "pd" and k[2].endswith("/60") for k in installed(trace, p))
