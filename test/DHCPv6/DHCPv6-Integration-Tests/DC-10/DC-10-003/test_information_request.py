def check(trace):
    for packet in trace.client("information_request"):
        assert len(packet.options(6)) == 1, "Missing ORO"
