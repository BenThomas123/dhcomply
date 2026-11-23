from lease_checks import timed, offers, retry


def check(trace):
    candidates, chosen = offers(trace)
    first, retry_packet = retry(trace, "solicit", 2)[:2]
    assert all(p.index > retry_packet.index for p in candidates)
    timed(trace, trace.client("request")[0].time, chosen.time)
