from lease_checks import leases, response, status


def check(trace):
    p = response(trace, "information_request")
    assert status(p) == trace.before["injected_status"]
    assert sorted(k[2] for k in leases(trace.after)) == sorted(trace.before["expected_resources_after_status"])
    assert [q.name for q in trace.packets if q.index > p.index and q.sport == 546] == trace.before["expected_followup_messages"]
