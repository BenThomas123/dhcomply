from validation_checks import evidence, incoming, resources


def check(trace):
    packet = incoming(trace, "reply")
    assigned = resources(packet, 3)
    events = trace.after["address_install_events"]
    failed = {e["address"] for e in events if e["interface"] == packet.iface
              and e["time"] >= packet.time and e["errno"] != 0}
    evidence(failed & assigned, "No observed failed OS address installation")
    assert failed.isdisjoint(trace.after["addresses"])
    assert failed.isdisjoint(trace.after["client_configured_addresses"])
    assert any(e["errno"] != 0 and e["address"] in failed for e in trace.after["client_error_events"])
