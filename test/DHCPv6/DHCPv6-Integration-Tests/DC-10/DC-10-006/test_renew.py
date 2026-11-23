from validation_checks import oro


def check(trace):
    for packet in trace.client("renew"):
        assert 82 in oro(packet), "Missing SOL_MAX_RT request"
