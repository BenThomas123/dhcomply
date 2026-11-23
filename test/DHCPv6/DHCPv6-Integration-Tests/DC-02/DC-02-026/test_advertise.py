from validation_checks import bare_control, evidence, exchange, progressed, tlvs


def check(trace):
    origin, packet = exchange(trace, "advertise")
    bare_control(trace, origin, packet, 17)
    values = packet.options(17)
    evidence(values and len(values[0]) >= 4, "Missing vendor enterprise identifier")
    evidence(int.from_bytes(values[0][:4], "big") not in trace.before["supported_enterprises"],
             "Enterprise is already supported by the client")
    tlvs(values[0][4:])
    progressed(trace, packet)
