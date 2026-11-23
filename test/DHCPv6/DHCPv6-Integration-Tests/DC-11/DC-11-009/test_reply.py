from timing_checks import response, unchanged_leases


def check(trace):
    response(trace, trace.client("information_request")[0])
    unchanged_leases(trace)
