from validation_checks import evidence


def check(trace):
    fragments = trace.before["ipv6_fragments"]
    evidence(fragments and any(f["more"] for f in fragments) and all(f["more"] for f in fragments),
             "Missing incomplete fragment sequence")
    evidence(trace.after["sample_time"] >= trace.before["reassembly_deadline"], "Incomplete observation window")
    assert trace.after["configuration"] == trace.before["configuration"]
