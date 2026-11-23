from validation_checks import evidence, exchange


def check(trace):
    origin, packet = exchange(trace, "reply")
    responses = [p for p in trace.server("reply") if p.iface == origin.iface]
    evidence(any(p.xid != origin.xid for p in responses) and any(
        any(len(s) >= 2 and int.from_bytes(s[:2], "big") != 0 for s in p.options(13)) for p in responses),
        "Expected invalid and failure Replies")
    times = [p.time for p in trace.packets if p.iface == origin.iface and p.sport == 546]
    window, limit = trace.before["rate_window_seconds"], trace.before["max_client_messages"]
    evidence(window > 0 and limit > 0 and trace.after["sample_time"] - origin.time >= window, "Incomplete rate window")
    assert all(sum(t <= v < t + window for v in times) <= limit for t in times)
