from lease_checks import tlvs, associations, response, deadlines


def check(trace):
    p = response(trace, "renew")
    unknown = trace.before["unknown_option_code"]
    assert any(c == unknown for _, _, _, _, nested in associations(p) for code, data in nested if code == 5 for c, _ in tlvs(data[24:]))
    deadlines(trace, p)
