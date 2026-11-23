from lease_checks import associations


def check(trace):
    p = trace.client("solicit")[0]
    assert any(code == 26 and len(value) >= 25 and value[8] == 56 and value[9:25] == bytes(16)
               for kind, _, _, _, nested in associations(p) if kind == "pd"
               for code, value in nested)
