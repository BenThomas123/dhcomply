from lease_checks import retry


def check(trace):
    packets = retry(trace, "renew", 3)
    for first, second, limits in zip(packets, packets[1:], trace.before["retry_windows"]):
        assert limits[0] <= second.time - first.time <= limits[1]
    assert len(trace.before["retry_windows"]) >= 2
