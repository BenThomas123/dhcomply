def check(trace):
    for packet in trace.client("rebind"):
        for code in [1,8,6]:
            assert len(packet.options(code)) == 1, f"Missing or repeated required option {code}"
        assert packet.options(3) or packet.options(25), "Missing identity association"
