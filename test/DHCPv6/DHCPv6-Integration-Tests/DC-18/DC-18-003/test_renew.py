from lease_checks import associations, leases


def check(trace):
    p = trace.client("renew")[0]
    previous = leases(trace.before)
    bound = {k[1] for k in previous if k[0] == "pd"}
    missing = set(trace.before["configured_iaids"]["pd"]) - bound
    assert bound and missing and missing <= {i for kind, i, *_ in associations(p) if kind == "pd"}
    for kind, iaid, _, _, nested in associations(p):
        if kind == "pd" and iaid in missing:
            for code, value in nested:
                if code == 26:
                    assert len(value) >= 25 and value[8] <= 128 and value[9:25] == bytes(16)
