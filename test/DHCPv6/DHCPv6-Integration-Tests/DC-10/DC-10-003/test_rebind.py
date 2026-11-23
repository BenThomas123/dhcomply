def check(trace):
    for packet in trace.client("rebind"):
        assert len(packet.options(6)) == 1, "Missing ORO"
