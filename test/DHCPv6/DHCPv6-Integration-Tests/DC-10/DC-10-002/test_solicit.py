def check(trace):
    for packet in trace.client("solicit"):
        for code in [5,7,9,12,18,19,26,2]:
            assert not packet.options(code), f"Prohibited top-level option {code}"
