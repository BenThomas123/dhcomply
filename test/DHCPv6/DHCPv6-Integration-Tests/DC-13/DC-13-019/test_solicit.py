from validation_checks import evidence


def check(trace):
    interfaces = trace.before["interfaces"]
    evidence(len(set(interfaces)) == 2, "Expected two independently monitored interfaces")
    window, limit = trace.before["rate_window_seconds"], trace.before["max_client_messages"]
    evidence(window > 0 and limit > 0, "Missing rate policy")
    for iface in interfaces:
        times = [p.time for p in trace.client("solicit") if p.iface == iface]
        evidence(len(times) >= 2, "Incomplete per-interface retry trace")
        assert all(sum(t <= v < t + window for v in times) <= limit for t in times)
    healthy = [p.time for p in trace.client("solicit") if p.iface == trace.before["healthy_interface"]]
    control = trace.before["healthy_control_intervals"]
    evidence(len(control) == len(healthy) - 1, "Healthy interface requires a paired control")
    assert all(abs(b - a - expected) <= trace.before["clock_tolerance"]
               for a, b, expected in zip(healthy, healthy[1:], control))
