from lease_checks import one, status


def check(trace):
    p = trace.server("advertise")[0]
    assert status(p) > 0
    options = [(82, "sol_max_rt"), (83, "inf_max_rt")]
    present = [(code, key) for code, key in options if p.options(code)]
    assert present
    for code, key in present:
        value = int.from_bytes(one(p, code), "big")
        assert 60 <= value <= 86400 and trace.after[key] == value
