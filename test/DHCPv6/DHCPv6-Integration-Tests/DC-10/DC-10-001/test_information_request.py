def check(trace):
    for packet in trace.client("information_request"):
        for code in [8,6]:
            assert len(packet.options(code)) == 1, f"Missing or repeated required option {code}"
