"""Outgoing packet checks for DC-01.

Exchange captures are scoped to a single stimulus. Where the message type is
itself under test, the driver records the outgoing packet indices independently
of the decoder. Interface/address snapshots are taken from the test host.
"""

from ipaddress import IPv6Address

from conformance import Inconclusive, NAMES, tlvs


def require(condition, why):
    if not condition:
        raise Inconclusive(why)


def check_formation(trace, case, name):
    if case == 5:
        indices = trace.after["outgoing_indices"]
        require(indices, "missing independently recorded transmission indices")
        for index in indices:
            packet = trace.packets[index]
            assert packet.direction == "client" and packet.name == name, (
                f"expected {name} at {index}, observed {packet.name}")
        return
    packets = trace.client(name)
    if case in (1, 2, 3):
        for p in packets:
            if case == 1:
                assert p.sport == 546, f"source UDP port {p.sport}"
            elif case == 2:
                assert p.dport == 547, f"destination UDP port {p.dport}"
            else:
                assert p.dst == "ff02::1:2", f"destination {p.dst}"
    elif case == 4:
        offers = [p for p in trace.server("advertise") if p.options(12)]
        require(offers, "no Advertise with Server Unicast option")
        followup = [p for p in packets if p.index > offers[0].index]
        assert followup, "missing follow-up exchange"
        assert all(p.dst == "ff02::1:2" for p in followup), "obsolete unicast used"
    elif case in (6, 9):
        for p in packets:
            assert len(p.raw) >= 4, "incomplete DHCPv6 header"
            assert NAMES[p.raw[0]] == name
            try:
                options = list(tlvs(p.raw[4:]))
            except ValueError as exc:
                raise AssertionError(str(exc)) from exc
            if case == 9:
                for code in trace.before["enabled_option_codes"]:
                    assert any(k == code for k, _ in options), f"missing enabled option {code}"
                for code, data in options:
                    assert code != 0, "reserved option zero"
                    if code in (7, 8, 14, 20, 32, 82, 83):
                        assert len(data) == {7:1, 8:2, 14:0, 20:0, 32:4, 82:4, 83:4}[code]
                    if code == 6:
                        assert len(data) % 2 == 0, "partial requested option code"
                    if code in (3, 25):
                        assert len(data) >= 12, "partial IA header"
                        try:
                            list(tlvs(data[12:]))
                        except ValueError as exc:
                            raise AssertionError(str(exc)) from exc
    elif case == 7:
        starts = trace.after["exchange_starts"]
        require(len(set(starts)) >= 2, "two separately initiated exchanges required")
        first = [trace.packets[i] for i in starts]
        require(all(p.name == name and p.direction == "client" for p in first),
                "exchange markers do not identify the tested messages")
        if len({p.xid for p in first}) == 1:
            raise Inconclusive("identical sample; capture additional independent exchanges")
    elif case == 8:
        assert len(packets) >= 3, "expected initial message and at least two retries"
        assert len({(p.iface, p.xid) for p in packets}) == 1, "retry changed interface or XID"
    elif case in (10, 11):
        target = trace.before["upstream_interface"]
        require(len(set(trace.before["active_interfaces"])) >= 2, "two active interfaces required")
        for p in packets:
            assert p.iface == target, f"sent on {p.iface}, expected {target}"
            assert p.options(3 if case == 10 else 25), "requested IA missing"
    elif case == 12:
        peers = trace.before["interface_servers"]
        require(len(peers) == 2, "two independently configured interfaces required")
        for iface, duid in peers.items():
            selected = [p for p in packets if p.iface == iface]
            crossed = [p for p in trace.server("advertise") if p.iface == iface
                       and p.options(2) and p.options(2) != [bytes.fromhex(duid)]]
            require(crossed, f"missing crossed offer on {iface}")
            assert selected and all(p.options(2) == [bytes.fromhex(duid)] for p in selected)
    elif case == 13:
        for p in packets:
            addresses = [IPv6Address(s) for s in trace.before["addresses"][p.iface]]
            require(any(a.is_link_local for a in addresses) and
                    any(not a.is_link_local for a in addresses), "both address scopes required")
            assert IPv6Address(p.src) in addresses
            assert IPv6Address(p.src).is_link_local, f"unexpected source {p.src}"
    elif case in (14, 15):
        if case == 14:
            require(trace.before["server_listen_port"] != 547, "wrong-port fixture required")
        else:
            errors = trace.after["icmpv6_errors"]
            require(any(e["type"] == 1 and e["code"] == 4 and
                        e["quoted_xid"] == packets[0].xid and
                        packets[0].time <= e["time"] for e in errors),
                    "missing correlated ICMPv6 Port Unreachable")
        require(not any(p.direction == "server" and p.dport == 546 and
                        p.name in ("advertise", "reply") for p in trace.packets), "unexpected valid response")
        assert len(packets) >= 2 and packets[1].xid == packets[0].xid, "exchange did not retry"
        assert trace.before["leases"] == trace.after["leases"], "lease state changed"
