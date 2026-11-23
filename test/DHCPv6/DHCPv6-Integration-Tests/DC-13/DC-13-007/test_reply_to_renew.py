from validation_checks import evidence, exchange, member_ias


def check(trace):
    origin, packet = exchange(trace, "reply", "renew")
    requested = member_ias(origin)
    missing = requested - member_ias(packet)
    evidence(len(requested) >= 2 and missing and missing != requested, "Expected partial IA omission")
    candidates = [p for p in trace.packets if p.index > packet.index and p.sport == 546
                  and p.iface == origin.iface and p.name in ("request", "renew", "rebind", "solicit")]
    assert any(missing <= member_ias(p) for p in candidates), "No recovery exchange for omitted IA"
