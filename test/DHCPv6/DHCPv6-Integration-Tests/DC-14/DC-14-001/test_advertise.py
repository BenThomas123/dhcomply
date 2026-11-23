from lease_checks import timed, offers, preference


def check(trace):
    candidates, chosen = offers(trace)
    assert preference(chosen) == 100
    solicit = trace.client("solicit")[0]
    request = trace.client("request")[0]
    deadline = solicit.time + trace.before["first_rt"]
    assert solicit.time < chosen.time < deadline
    assert len(candidates) == 1
    timed(trace, request.time, deadline)
