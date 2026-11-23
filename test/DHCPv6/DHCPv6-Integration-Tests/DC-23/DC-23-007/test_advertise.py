from validation_checks import evidence, exchange, rejected


def check(trace):
    origin, packet = exchange(trace, "advertise")
    code = trace.before["duplicated_option_code"]
    evidence(code in (1, 2) and len(set(packet.options(code))) >= 2, "Expected conflicting singleton IDs")
    policy = trace.before["duplicate_option_policy"]
    evidence(policy in ("discard", "first", "last"), "A documented duplicate option policy is required")
    if policy == "discard":
        rejected(trace, origin, packet)
    else:
        index = 0 if policy == "first" else -1
        chosen = packet.options(code)[index]
        if code == 1 and [chosen] != origin.options(1):
            rejected(trace, origin, packet)
        else:
            field = "client_duid" if code == 1 else "server_duid"
            assert trace.after["selected_identifiers"][field] == chosen.hex()
