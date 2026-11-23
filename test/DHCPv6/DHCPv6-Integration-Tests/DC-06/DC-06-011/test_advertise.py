from lease_checks import duid, associations, bindings, offers


def check(trace):
    candidates, chosen = offers(trace)
    wanted = {k for k, *_ in associations(trace.client("solicit")[0])}
    assert wanted == {"na", "pd"}
    assert any({k[0] for k in bindings(p)} < wanted for p in candidates)
    assert any({k[0] for k in bindings(p)} == wanted for p in candidates)
    assert {k[:2] for k in bindings(trace.client("request")[0])} <= {k[:2] for k in bindings(chosen)}
    assert duid(chosen, 2).hex() == trace.before["policy_selected_server"]
