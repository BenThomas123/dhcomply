from timing_checks import exchange, silent
from lease_clock_checks import resources


def check(trace):
    sent = exchange(trace, "release")
    silent(trace, sent)
    assert len(sent) <= 4
    assert trace.after["unusable_at"] <= sent[0].time <= trace.after["shutdown_at"]
    released = resources(sent[0])
    assert released, "Release has no resources"
    assert released <= set(trace.before["leases"])
    assert not released.intersection(trace.after["leases"])
