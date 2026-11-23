from lease_checks import leases


def check(trace):
    p = trace.server("reply")[0]
    raw = bytes(p.payload)
    option = trace.before["damaged_identifier_code"]
    assert option in (1, 2)
    length_offset = trace.before["identifier_length_offset"]
    assert int.from_bytes(raw[length_offset-2:length_offset], "big") == option
    assert int.from_bytes(raw[length_offset:length_offset+2], "big") > len(raw) - length_offset - 2
    assert trace.after["client_alive"]
    assert trace.client(trace.before["outstanding_message"])[-1].index > p.index
    assert leases(trace.after) == leases(trace.before)
