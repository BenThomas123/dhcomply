from lease_checks import offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    initial = trace.client("solicit")[0]
    bad = [p for p in trace.server("advertise") if p.index < chosen.index and (p.xid != initial.xid or p.options(1) != initial.options(1))]
    assert bad and all(p.options(2) != chosen.options(2) for p in bad)
    assert any(preference(p) == 255 for p in bad) and preference(chosen) == 10
