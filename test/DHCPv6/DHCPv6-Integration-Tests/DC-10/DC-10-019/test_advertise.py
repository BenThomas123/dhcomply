from validation_checks import evidence, incoming, tlvs


def check(trace):
    packet = incoming(trace, "advertise")
    enterprise = trace.before["vendor_enterprise"]
    expected = trace.before["supported_vendor_suboptions"]
    values = [v for v in packet.options(17) if len(v) >= 4 and int.from_bytes(v[:4], "big") == enterprise]
    evidence(len(values) == 1, "Expected one configured enterprise")
    received = {str(k): v.hex() for k, v in tlvs(values[0][4:])}
    supported = {k: v for k, v in received.items() if k in expected}
    evidence(supported and len(received) > len(supported), "Need supported and unsupported suboptions")
    assert trace.after["applied_vendor_suboptions"] == supported
