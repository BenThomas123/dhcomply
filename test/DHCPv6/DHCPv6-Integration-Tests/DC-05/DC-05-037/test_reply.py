from lease_checks import bindings, no_use


def check(trace):
    p = trace.server("reply")[0]
    malformed = False
    try:
        bindings(p)
    except (AssertionError, ValueError):
        malformed = True
    assert malformed, "Capture must contain an invalid IA suboption"
    no_use(trace, {tuple(trace.before["invalid_lease"])})
    assert trace.after["client_alive"]
