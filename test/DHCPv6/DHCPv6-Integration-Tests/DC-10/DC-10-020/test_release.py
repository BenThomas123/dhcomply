from validation_checks import check_nesting


def check(trace):
    for packet in trace.client("release"):
        check_nesting(packet.raw[4:])
