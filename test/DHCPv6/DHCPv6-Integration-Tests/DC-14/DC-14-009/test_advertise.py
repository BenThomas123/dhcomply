from lease_checks import duid, bindings, offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    assert len({duid(p, 2) for p in candidates}) >= 2 and all(preference(p) == 100 for p in candidates)
    assert len({frozenset(bindings(p)) for p in candidates}) >= 2
    assert duid(chosen, 2).hex() == trace.before["policy_selected_server"]
