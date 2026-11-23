from validation_checks import check_nesting, evidence, incoming, unchanged


def check(trace):
    packet = incoming(trace, "reply")
    try:
        check_nesting(packet.raw[4:])
    except AssertionError:
        unchanged(trace)
    else:
        evidence(False, "No illegally nested IA suboption in stimulus")
