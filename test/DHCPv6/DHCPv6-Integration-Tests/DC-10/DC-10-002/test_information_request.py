def check(trace):
    for packet in trace.client("information_request"):
        # A response to Reconfigure carries the requesting server's identifier.
        for code in (3, 5, 7, 9, 12, 14, 18, 19, 25, 26):
            assert not packet.options(code), f"Prohibited top-level option {code}"
