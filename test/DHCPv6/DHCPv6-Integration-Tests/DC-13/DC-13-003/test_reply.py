from validation_checks import caps, evidence


def check(trace):
    offers = trace.server("reply")
    evidence(len({p.options(2)[0] for p in offers if p.options(2)}) >= 2, "Need two identified servers")
    evidence(len({caps(p, 83) for p in offers}) >= 2, "Need conflicting, valid caps")
    assert trace.after["effective_cap_seconds"] == trace.before["default_cap_seconds"]
