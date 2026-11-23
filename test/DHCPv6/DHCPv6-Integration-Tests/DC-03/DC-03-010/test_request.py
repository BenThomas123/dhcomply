from timing_checks import same_retransmission


def check(trace):
    same_retransmission(trace, "request", False)
