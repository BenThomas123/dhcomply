from lease_checks import response, status


def check(trace):
    p = response(trace, "request")
    assert status(p) == 1
    window = trace.before["minimum_retry_interval"]
    duration = trace.before["maximum_retry_duration"]
    assert 0 < window <= duration <= trace.after["time"] - p.time
    retries = [q for q in trace.client("request") if q.index > p.index and q.options(2) == p.options(2)]
    assert all(q.time >= p.time + window and q.time <= p.time + duration for q in retries)
    assert all(b.time - a.time >= window for a, b in zip(retries, retries[1:]))
