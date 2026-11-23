from lease_checks import duid, associations, bindings, offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    wanted = {k for k, *_ in associations(trace.client("solicit")[0])}
    assert wanted == {"na", "pd"}
    assert any({k[0] for k in bindings(p)} == {"na"} and preference(p) == 200 for p in candidates)
    assert any({k[0] for k in bindings(p)} == wanted and preference(p) == 100 for p in candidates)
    assert {k[:2] for k in bindings(trace.client("request")[0])} <= {k[:2] for k in bindings(chosen)}
    assert duid(chosen, 2).hex() == trace.before["policy_selected_server"]
