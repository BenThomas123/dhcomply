def check(trace):
    for packet in trace.client("request"):
        for code in [1,2,8,6]:
            assert len(packet.options(code)) == 1, f"Missing or repeated required option {code}"
