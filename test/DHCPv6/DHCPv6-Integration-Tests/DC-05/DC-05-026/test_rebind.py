from lease_checks import associations, bindings, timed


def check(trace):
    p = trace.client("rebind")[0]
    grant = trace.server("reply")[0]
    ias = {(k, i): (t1, t2) for k, i, t1, t2, _ in associations(grant) if 0 < t1 < t2}
    assert ias and grant.index < p.index
    for kind, i, *_ in associations(p):
        if (kind, i) in ias:
            t1, t2 = ias[kind, i]
            deadline = t1 if p.name == "renew" else t2
            if deadline:
                timed(trace, p.time, grant.time + deadline)
            else:
                limits = [valid for k, (_, valid) in bindings(grant).items() if k[:2] == (kind, i)]
                assert limits and 0 < p.time - grant.time <= min(limits)
            break
    else:
        raise AssertionError("Expected affected IA in outgoing exchange")
