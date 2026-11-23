from validation_checks import associations, evidence, incoming, resources


def check(trace):
    packet = incoming(trace, "reply")
    entries = associations(packet, 3)
    evidence(any(sum(code == 5 for code, _ in children) >= 2 for _, _, children in entries.values()),
             "Need two child resources inside the same IA")
    assert resources(packet, 3).issubset(trace.after["addresses"])
