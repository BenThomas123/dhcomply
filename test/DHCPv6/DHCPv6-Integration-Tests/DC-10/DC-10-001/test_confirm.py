def check(trace):
    for packet in trace.client("confirm"):
        for code in [1,8]:
            assert len(packet.options(code)) == 1, f"Missing or repeated required option {code}"
        assert packet.options(3), "Missing identity association"
