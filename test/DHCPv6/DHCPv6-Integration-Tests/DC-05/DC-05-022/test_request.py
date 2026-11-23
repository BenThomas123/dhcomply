from lease_checks import bindings, response, deadlines


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    assert any(valid == 0xffffffff for _, valid in records.values())
    assert trace.after["time"] > p.time
    deadlines(trace, p)
