from validation_checks import evidence


def check(trace):
    expiry = trace.before["last_valid_until"]
    evidence(trace.after["sample_time"] > expiry and trace.before["sample_time"] < expiry, "Window must cross expiry")
    rebinds = trace.client("rebind")
    evidence(any(p.time < expiry for p in rebinds), "Need ongoing Rebind at start")
    assert all(p.time < expiry for p in rebinds), "Rebind continued after final lease expiry"
