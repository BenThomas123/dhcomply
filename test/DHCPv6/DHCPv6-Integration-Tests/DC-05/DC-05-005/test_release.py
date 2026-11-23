from lease_checks import associations


def check(trace):
    p = trace.client("release")[0]
    permitted = {"confirm": {"na"}, "decline": {"na"}, "information_request": set()}
    assert {k for k, *_ in associations(p)} <= permitted.get(p.name, {"na", "pd"})
