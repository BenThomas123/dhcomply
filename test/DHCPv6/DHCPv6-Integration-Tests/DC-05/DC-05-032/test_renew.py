from lease_checks import associations


def check(trace):
    p = trace.client("renew")[0]
    replies = trace.server("reply")
    assert len(replies) >= 2 and all(any(t1 == t2 == 0 for _, _, t1, t2, _ in associations(r)) for r in replies)
    packets = trace.client("renew")
    assert all(b.time - a.time >= trace.before["minimum_retry_interval"] for a, b in zip(packets, packets[1:]))
    assert trace.after["time"] - p.time >= trace.before["minimum_retry_interval"] > 0
