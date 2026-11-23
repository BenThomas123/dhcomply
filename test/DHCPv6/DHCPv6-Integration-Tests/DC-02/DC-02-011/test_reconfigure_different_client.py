from validation_checks import evidence, incoming, require_reconfigure, unchanged


def check(trace):
    packet = incoming(trace, "reconfigure")
    require_reconfigure(trace, packet)
    evidence(packet.options(1) and packet.options(1)[0].hex() != trace.before["client_duid"], "Missing the specified Reconfigure stimulus")
    unchanged(trace)
    evidence(trace.after["sample_time"] >= packet.time + trace.before["reaction_window_seconds"] > packet.time,
             "Capture does not span the configured response window")
    assert not [p for p in trace.packets if p.index > packet.index and p.iface == packet.iface
                and p.time <= trace.after["sample_time"] and p.sport == 546 and p.name in ("renew", "rebind", "information_request")]
