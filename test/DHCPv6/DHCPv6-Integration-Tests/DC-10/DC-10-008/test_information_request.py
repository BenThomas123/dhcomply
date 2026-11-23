import collections

from validation_checks import tlvs


def check(trace):
    for packet in trace.client("information_request"):
        counts = collections.Counter(code for code, _ in tlvs(packet.raw[4:]))
        for code in (1, 2, 6, 7, 8, 9, 11, 13, 14, 15, 18, 19, 20, 32, 82, 83):
            assert counts[code] <= 1, f"Repeated singleton {code}"
