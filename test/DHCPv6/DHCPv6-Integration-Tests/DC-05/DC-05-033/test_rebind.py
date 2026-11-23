from lease_checks import associations


def check(trace):
    p = trace.client("rebind")[0]
    grant = trace.server("reply")[0]
    field = 2 if p.name == "renew" else 3
    rows = associations(grant)
    assert len({r[field] for r in rows}) >= 2
    for row in rows:
        matching = [q for q in trace.client("rebind") if q.index > grant.index and any(ia[:2] == row[:2] for ia in associations(q))]
        assert matching and matching[0].time <= grant.time + row[field] + trace.before["tolerance"]
