from validation_checks import oro


def check(trace):
    for packet in trace.client("information_request"):
        forbidden = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 20, 25, 26}
        assert forbidden.isdisjoint(oro(packet)), "Prohibited code in ORO"
