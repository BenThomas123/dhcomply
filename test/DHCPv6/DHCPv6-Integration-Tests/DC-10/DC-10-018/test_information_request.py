from validation_checks import evidence


def check(trace):
    packet = trace.client("information_request")[0]
    enterprise = trace.before["vendor_enterprise"]
    expected = [bytes.fromhex(s) for s in trace.before["vendor_class_values"]]
    evidence(expected, "Configure vendor-class strings")
    matches = [v[4:] for v in packet.options(16) if len(v) >= 4 and int.from_bytes(v[:4], "big") == enterprise]
    assert len(matches) == 1
    data = matches[0]
    values = []
    while data:
        assert len(data) >= 2
        length = int.from_bytes(data[:2], "big")
        assert 0 < length <= len(data) - 2
        values.append(data[2:2 + length])
        data = data[2 + length:]
    assert values == expected
