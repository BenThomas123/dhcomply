from lease_checks import response, mixed_status


def check(trace):
    p = response(trace, "request")
    mixed_status(trace, p, trace.before["failed_ia_kind"], trace.before["injected_status"])
