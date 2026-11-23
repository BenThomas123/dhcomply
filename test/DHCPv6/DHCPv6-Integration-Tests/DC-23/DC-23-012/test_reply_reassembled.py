from validation_checks import evidence, incoming, progressed


def check(trace):
    packet = incoming(trace, "reply")
    fragments = trace.before["ipv6_fragments"]
    evidence(len(fragments) >= 2 and len({f["id"] for f in fragments}) == 1, "Missing fragment capture")
    fragments = sorted(fragments, key=lambda f: f["offset_bytes"])
    offset = 0
    pieces = []
    for i, item in enumerate(fragments):
        data = bytes.fromhex(item["fragment_payload"])
        evidence(item["offset_bytes"] == offset and item["more"] == (i < len(fragments)-1),
                 "Noncontiguous fragments")
        evidence(not item["more"] or len(data) % 8 == 0, "Unaligned non-final fragment")
        pieces.append(data)
        offset += len(data)
    evidence(b"".join(pieces)[8:] == packet.raw, "Kernel reassembly differs from captured Reply")
    progressed(trace, packet)
