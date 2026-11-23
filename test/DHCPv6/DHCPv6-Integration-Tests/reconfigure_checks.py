import hmac
from ipaddress import IPv6Address

from conformance import NotApplicable
from timing_checks import number, require, tlvs, unchanged_leases


TYPES = {5: "renew", 6: "rebind", 11: "information_request"}


def only(packet, code):
    opts = packet.options(code)
    require(len(opts) == 1, f"capture needs one option {code}")
    return opts[0]


def association(trace, packet):
    key = only(packet, 2).hex()
    return trace.before["associations"].get(packet.iface, {}).get(key)


def valid_mac(packet, context):
    data = only(packet, 11)
    require(len(data) == 28 and data[:3] == bytes((3, 1, 0)) and data[11] == 2,
            "RKAP with HMAC-MD5 and monotonically increasing replay values is required")
    pos = 4
    for code, value in tlvs(packet.raw[4:]):
        if code == 11:
            start = pos + 4 + 12
            normalized = packet.raw[:start] + bytes(16) + packet.raw[start + 16:]
            key = bytes.fromhex(context["rkap_key"])
            require(len(key) == 16, "RKAP keys must be 128 bits")
            return hmac.compare_digest(hmac.digest(key, normalized, "md5"), data[12:])
        pos += 4 + len(value)
    raise AssertionError("missing Authentication option")


def verify_context(trace, packet, *, wrong_client=False, bad_mac=False, replay=False):
    if trace.before.get("rkap_supported") is False:
        raise NotApplicable("DUT does not implement the optional RKAP feature")
    context = association(trace, packet)
    require(context, "capture needs established server association")
    require((only(packet, 1).hex() != context["client_duid"].lower()) == wrong_client,
            "unexpected Client Identifier for this case")
    require(valid_mac(packet, context) != bad_mac, "unexpected integrity result for this case")
    counter = int.from_bytes(only(packet, 11)[3:11], "big")
    require((counter <= context["last_replay"]) == replay, "unexpected replay counter")
    return context


def initiated(trace, packet, until=None):
    return [p for p in trace.packets if p.iface == packet.iface and
            p.name in ("solicit", "request", "renew", "rebind", "confirm", "decline",
                       "release", "information_request") and
            p.index > packet.index and (until is None or p.index < until)]


def no_action(trace, packet):
    duration = trace.before["observation_seconds"]
    require(duration > 0 and trace.after["end"] >= packet.time + duration,
            "observation ended before quiet response window")
    assert not [p for p in initiated(trace, packet) if p.time <= packet.time + duration]


def rejected(trace, kind):
    trigger = trace.server("reconfigure")[0]
    if kind in ("no_context", "disabled"):
        if kind == "disabled":
            require(trace.before["reconfigure_accept"] is False, "disable Reconfigure acceptance")
        require(not association(trace, trigger), "trigger has an established server association")
    elif kind == "server":
        contexts = trace.before["associations"][trigger.iface]
        require(contexts and not association(trace, trigger), "need a different server identifier")
    elif kind == "no_auth":
        require(association(trace, trigger) and not trigger.options(11), "omit only authentication")
    elif kind == "multicast":
        verify_context(trace, trigger)
        require(IPv6Address(trigger.dst).is_multicast, "capture requires multicast delivery")
    elif kind == "client":
        verify_context(trace, trigger, wrong_client=True)
    elif kind == "bad_mac":
        verify_context(trace, trigger, bad_mac=True)
    elif kind in ("missing_type", "invalid_type", "request_type"):
        verify_context(trace, trigger)
        if kind == "missing_type":
            require(not trigger.options(19), "omit Reconfigure Message option")
        else:
            code = number(trigger, 19, 1)
            require(code == 3 if kind == "request_type" else code not in TYPES, "unsupported type required")
    no_action(trace, trigger)


def triggered(trace, name, keep=False):
    if trace.before.get("rkap_supported") is False:
        raise NotApplicable("DUT does not implement the optional RKAP feature")
    trigger = trace.server("reconfigure")[0]
    verify_context(trace, trigger)
    require(not IPv6Address(trigger.dst).is_multicast, "unicast Reconfigure required")
    require(TYPES.get(number(trigger, 19, 1)) == name, "mismatched trigger message")
    next_packets = initiated(trace, trigger)
    assert next_packets and next_packets[0].name == name
    packet = next_packets[0]
    assert packet.xid != trigger.xid
    if name == "rebind":
        assert not packet.options(2)
    else:
        assert packet.options(2) == trigger.options(2)
    if keep:
        unchanged_leases(trace)
    return packet


def duplicate(trace, stale):
    first, *others = trace.server("reconfigure")
    require(others, "capture a second Reconfigure")
    second = others[0]
    name = TYPES.get(number(first, 19, 1))
    require(name, "valid trigger type required")
    selected = triggered(trace, name)
    require(selected.index < second.index and second.iface == first.iface
            and second.options(2) == first.options(2), "capture both triggers on the active association")
    if stale:
        require(second.raw == first.raw, "capture must contain replay of the accepted Reconfigure")
        # Observe replay after completion, distinguishing replay detection from in-flight suppression.
        require(any(p.name == "reply" and p.iface == first.iface and p.xid == selected.xid and
                    selected.index < p.index < second.index for p in trace.packets),
                "finish first exchange before replay")
        no_action(trace, second)
    else:
        verify_context(trace, second)
        require(int.from_bytes(only(second, 11)[3:11], "big") >
                int.from_bytes(only(first, 11)[3:11], "big"), "use fresh second trigger")
        require(not any(p.name == "reply" and p.iface == first.iface and p.xid == selected.xid and
                        selected.index < p.index < second.index for p in trace.packets),
                "second trigger must arrive during active exchange")
        require(trace.after["end"] >= second.time + trace.before["observation_seconds"],
                "observe through response window")
        assert all(p.name == name and p.xid == selected.xid for p in initiated(trace, second))


def failed_refresh(trace, name):
    sent = triggered(trace, name)
    require(not any(p.name == "reply" and p.iface == sent.iface and p.xid == sent.xid and
                    p.index > sent.index for p in trace.packets), "withhold the reply")
    require(trace.after["end"] >= sent.time + trace.before["observation_seconds"], "observation too short")
    unchanged_leases(trace)


def logging(trace):
    messages = trace.server("reconfigure")
    good = []
    for p in messages:
        ctx = association(trace, p)
        require(ctx, "logged messages must use a known association")
        good.append(valid_mac(p, ctx))
    require(any(good) and not all(good), "capture one valid and one failed authentication")
    entries = "\n".join(trace.after["log_lines"]).lower()
    assert "reconfigur" in entries and any(w in entries for w in ("reject", "invalid", "discard", "fail"))
    for p in messages:
        assert association(trace, p)["rkap_key"].lower() not in entries


def independent(trace):
    messages = trace.server("reconfigure")
    require(len(messages) == 2, "need two server contexts")
    require(messages[0].options(2) != messages[1].options(2), "use distinct server DUIDs")
    for i, packet in enumerate(messages):
        verify_context(trace, packet)
        name = TYPES.get(number(packet, 19, 1))
        require(name in ("renew", "information_request"), "use a server-identifying response")
        following = initiated(trace, packet, messages[1].index if i == 0 else None)
        assert following and following[0].name == name
        assert following[0].options(2) == packet.options(2)
