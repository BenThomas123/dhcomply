from validation_checks import evidence


def check(trace):
    reconnect = trace.before["link_restored_at"]
    evidence(trace.before["valid_until"] > reconnect, "Previous lease must still be valid")
    assert any(p.time >= reconnect and p.iface == trace.before["interface"] for p in trace.client("rebind"))
