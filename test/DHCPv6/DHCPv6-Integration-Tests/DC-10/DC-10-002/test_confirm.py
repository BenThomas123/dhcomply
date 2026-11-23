def check(trace):
    for packet in trace.client("confirm"):
        for code in [5,7,9,12,18,19,26,2,14]:
            assert not packet.options(code), f"Prohibited top-level option {code}"
