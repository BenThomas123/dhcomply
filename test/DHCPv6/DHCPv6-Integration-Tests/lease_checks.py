from ipaddress import IPv6Address, IPv6Network
from struct import unpack_from


def one(packet, code):
    values = packet.options(code)
    assert len(values) == 1, f"{packet.name} must contain exactly one option {code}"
    return values[0]


def duid(packet, code=1):
    data = one(packet, code)
    assert 2 < len(data) <= 128, "DUID size outside the wire range"
    kind = int.from_bytes(data[:2], "big")
    if kind in (1, 3):
        start = 8 if kind == 1 else 4
        assert len(data) > start and any(data[2:4]), "Missing hardware type or link address"
        if data[2:4] == b"\0\1":
            assert len(data) == start + 6
    elif kind == 2:
        assert len(data) > 6, "Missing enterprise identifier or vendor-specific identifier"
    elif kind == 4:
        assert len(data) == 18, "A UUID DUID must contain exactly 16 UUID octets"
    else:
        raise AssertionError(f"Unsupported DUID vector type {kind}")
    return data


def tlvs(data):
    items = []
    offset = 0
    while offset < len(data):
        assert offset + 4 <= len(data), "Truncated nested option header"
        code, length = unpack_from("!HH", data, offset)
        offset += 4
        assert length <= len(data) - offset, "Truncated nested option body"
        items.append((code, data[offset:offset + length]))
        offset += length
    return items


def associations(packet):
    result = []
    for code, kind in [(3, "na"), (25, "pd")]:
        for raw in packet.options(code):
            assert len(raw) >= 12, "Short IA fixed fields"
            iaid, t1, t2 = unpack_from("!III", raw)
            nested = tlvs(raw[12:])
            result.append((kind, iaid, t1, t2, nested))
    return result


def bindings(packet):
    """Map (kind, IAID, resource) to (preferred lifetime, valid lifetime)."""
    result = {}
    for kind, iaid, _, _, nested in associations(packet):
        for code, data in nested:
            if code == 5 and kind == "na":
                assert len(data) >= 24, "Short IA Address"
                resource = str(IPv6Address(data[:16]))
                lifetimes = unpack_from("!II", data, 16)
                tlvs(data[24:])
            elif code == 26 and kind == "pd":
                assert len(data) >= 25, "Short IA Prefix"
                resource = str(IPv6Network((IPv6Address(data[9:25]), data[8]), strict=False))
                lifetimes = unpack_from("!II", data)
                tlvs(data[25:])
            else:
                continue
            key = (kind, iaid, resource)
            assert key not in result, f"Duplicate lease entry {key}"
            result[key] = lifetimes
    return result


def leases(snapshot):
    return {(row["kind"], row["iaid"], row["resource"]): row for row in snapshot["leases"]}


def events(trace, name):
    return [e for e in trace.after["events"] if e["kind"] == name]


def event(trace, name):
    matches = events(trace, name)
    assert matches, f"Missing {name} stimulus/observation"
    return matches[0]


def response(trace, name, server="reply"):
    request = trace.client(name)[0]
    responses = [p for p in trace.server(server) if p.index > request.index and
                 p.iface == request.iface and p.xid == request.xid and
                 p.options(1) == request.options(1)]
    if name in ("request", "renew", "release", "decline"):
        responses = [p for p in responses if p.options(2) == request.options(2)]
    assert responses, f"Missing correlated {server} for {name}"
    return responses[0]


def installed(trace, packet):
    records = bindings(packet)
    active = {key for key, (pref, valid) in records.items() if 0 < valid and pref <= valid}
    assert active, "Response must grant at least one usable resource"
    state = leases(trace.after)
    for key in active:
        assert key in state, f"Missing lease {key}"
        target = "addresses" if key[0] == "na" else "prefixes"
        assert key[2] in trace.after[target], f"Missing host configuration {key}"
    return active


def deadlines(trace, packet):
    records = bindings(packet)
    for key in installed(trace, packet):
        row = leases(trace.after)[key]
        for field, seconds in zip(("preferred_until", "valid_until"), records[key]):
            if seconds == 0xffffffff:
                assert row[field] is None, "Infinite lifetime became finite"
            else:
                assert abs(row[field] - packet.time - seconds) <= trace.before["tolerance"], (key, field)


def timed(trace, actual, expected):
    assert abs(actual - expected) <= trace.before["tolerance"], (actual, expected)


def preserved(trace, keys):
    assert keys, "Fixture needs a previously held binding"
    before, after = leases(trace.before), leases(trace.after)
    for key in keys:
        assert key in after, f"Binding unexpectedly lost: {key}"
        assert before[key]["valid_until"] == after[key]["valid_until"], key
        assert before[key]["preferred_until"] == after[key]["preferred_until"], key


def no_use(trace, keys):
    assert keys, "Fixture needs a withdrawn resource"
    for key in keys:
        assert key not in leases(trace.after)
        assert key[2] not in trace.after["addresses" if key[0] == "na" else "prefixes"]


def offers(trace):
    solicit = trace.client("solicit")[0]
    request = trace.client("request")[0]
    candidates = [p for p in trace.server("advertise") if solicit.index < p.index < request.index
                  and p.xid == solicit.xid and p.iface == solicit.iface
                  and p.options(1) == solicit.options(1) and bindings(p)]
    selected = [p for p in candidates if one(p, 2) == one(request, 2)]
    assert selected, "Request must identify an eligible advertising server"
    return candidates, selected[0]


def preference(packet):
    data = packet.options(7)
    if not data:
        return 0
    assert len(data) == 1 and len(data[0]) == 1
    return data[0][0]


def first_after(trace, event_name, message_name):
    marker = event(trace, event_name)
    client_names = {"solicit", "request", "renew", "rebind", "confirm", "release", "decline", "information_request"}
    packets = [p for p in trace.packets if p.time >= marker["time"] and p.name in client_names]
    assert packets and packets[0].name == message_name, f"Expected {message_name} after {event_name}"
    return packets[0]


def status(packet):
    values = packet.options(13)
    assert len(values) == 1 and len(values[0]) >= 2, "Expected a status option"
    return int.from_bytes(values[0][:2], "big")


def mixed_status(trace, packet, failed_kind, error):
    ias = associations(packet)
    failures = {(kind, iaid) for kind, iaid, _, _, nested in ias if kind == failed_kind
                and any(c == 13 and len(data) >= 2 and int.from_bytes(data[:2], "big") == error
                        for c, data in nested)}
    assert failures, "Required IA-scoped error did not occur"
    success = installed(trace, packet)
    assert all(key[:2] not in failures for key in success)
    assert all(key[:2] not in failures for key in leases(trace.after) if key not in leases(trace.before))


def retry(trace, name, count):
    packets = trace.client(name)
    assert len(packets) >= count
    first = packets[0]
    for prev, nxt in zip(packets[:count-1], packets[1:count]):
        assert nxt.xid == first.xid and nxt.iface == first.iface and nxt.time > prev.time
        assert nxt.options(1) == first.options(1) and nxt.options(2) == first.options(2)
    return packets
