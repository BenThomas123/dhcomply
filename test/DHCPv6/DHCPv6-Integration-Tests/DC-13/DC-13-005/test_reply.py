from validation_checks import evidence, incoming, member_ias


def check(trace):
    packet = incoming(trace, "reply")
    pending = set(trace.before["pending_iaids"])
    completed = {iaid for _, iaid in member_ias(packet)}
    evidence(pending & completed and pending - completed, "Need a partial update across independent IAs")
    assert set(trace.after["pending_iaids"]) == pending - completed
    assert completed & pending <= set(trace.after["bound_iaids"])
