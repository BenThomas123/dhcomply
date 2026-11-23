from validation_checks import oro


def check(trace):
    for packet in trace.client("information_request"):
        assert 83 in oro(packet), "Missing INF_MAX_RT request"
