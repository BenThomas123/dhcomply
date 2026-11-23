"""Passive integration evidence for DC-02, DC-10, DC-13 and DC-23.

Packet indices come from the capture. before/after are observations at the
boundaries of the case's observation window. before["stimulus_index"] marks
the packet under test; before["origin_index"] marks its triggering client
packet. Optional control packets and host observations used by individual
tests are named explicitly at the point of use. Host "configuration" is a
snapshot of DHCP-owned addresses, routes, DNS and leases (no volatile clocks).
"capture_end" and timestamps use the packet capture clock in seconds. Case
inputs and control measurements belong to the fixture, never to the DUT.
"""

import ipaddress
import struct

from conformance import Inconclusive


def evidence(condition, message):
    if not condition:
        raise Inconclusive(message)


def indexed(trace, key):
    index = trace.before[key]
    packets = [p for p in trace.packets if p.index == index]
    evidence(len(packets) == 1, f"No unique captured packet at {key}={index}")
    return packets[0]


def incoming(trace, name):
    p = indexed(trace, "stimulus_index")
    evidence(p.name == name and p.direction == "server" and p.dport == 546,
             f"Expected inbound {name} at stimulus_index")
    return p


def exchange(trace, name, origin_name=None):
    packet = incoming(trace, name)
    origin = indexed(trace, "origin_index")
    evidence(origin.index < packet.index and origin.iface == packet.iface and origin.direction == "client",
             "Missing originating client exchange on the stimulus interface")
    if origin_name:
        evidence(origin.name == origin_name, f"Expected originating {origin_name}")
    if name == "reply" and origin.name == "solicit":
        evidence(origin.options(14) == [b""], "A direct Reply needs a Rapid Commit Solicit")
    return origin, packet


def unchanged(trace):
    # The two samples must bracket the stimulus and cover a nonzero window.
    p = indexed(trace, "stimulus_index")
    evidence(trace.before["sample_time"] <= p.time < trace.after["sample_time"],
             "State samples must bracket the stimulus")
    assert trace.after["configuration"] == trace.before["configuration"], "DHCP state changed"


def rejected(trace, origin, packet):
    unchanged(trace)
    # Retrying the same exchange proves it remained pending.
    responses = [p for p in trace.packets if packet.index < p.index and p.iface == origin.iface
                 and p.time <= trace.after["sample_time"] and p.sport == 546]
    evidence(responses or trace.after["sample_time"] >= trace.before["next_retry_deadline"],
             "Capture ends before any retry was due")
    assert responses and (responses[0].name, responses[0].xid) == (origin.name, origin.xid), (
        "Client did not continue its pending exchange"
    )


def bare_control(trace, origin, packet, altered_code=None, altered_xid=False):
    """Compare all uninterpreted TLVs and header fields outside the intended change."""
    control = indexed(trace, "control_index")
    evidence(control.name == packet.name and control.xid == origin.xid
             and control.iface == packet.iface and control.sport == packet.sport
             and control.dport == packet.dport, "Control must match exchange and transport")
    evidence(control.options(1) == origin.options(1) and len(control.options(2)) == 1,
             "Invalid identifier context in control")
    left = [(c, b) for c, b in tlvs(control.raw[4:]) if c != altered_code]
    right = [(c, b) for c, b in tlvs(packet.raw[4:]) if c != altered_code]
    evidence(left == right and (altered_xid or packet.xid == origin.xid),
             "Additional packet fields differ from control")


def tlvs(data):
    """Strict bounded decoder with offsets relative to the enclosing option."""
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("Truncated option header")
        code, size = struct.unpack_from("!HH", data, offset)
        offset += 4
        if size > len(data) - offset:
            raise ValueError("Option exceeds enclosing buffer")
        result.append((code, data[offset:offset + size]))
        offset += size
    return result


def malformed(data):
    try:
        tlvs(data)
    except ValueError:
        return True
    return False


def instrumented(trace):
    evidence(trace.before["sanitizers"] and trace.after["process_log_complete"],
             "Requires a captured instrumented DUT run")
    assert trace.after["pid"] == trace.before["pid"] and trace.after["process_alive"]
    assert not trace.after["sanitizer_diagnostics"], trace.after["sanitizer_diagnostics"]


def progressed(trace, packet):
    if packet.name == "advertise":
        next_packets = [p for p in trace.client("request") if p.index > packet.index and p.iface == packet.iface]
        assert next_packets and next_packets[0].options(2) == packet.options(2)
    else:
        # Observe the transaction consumed by the DUT's lease/DNS application hook.
        applied = trace.after["applied_transactions"]
        assert any(row["xid"] == packet.xid and row["interface"] == packet.iface
                   and row["server_duid"] == packet.options(2)[0].hex()
                   and row["time"] >= packet.time for row in applied)


def oro(packet):
    values = packet.options(6)
    assert len(values) == 1 and values[0] and len(values[0]) % 2 == 0, "Malformed or missing ORO"
    return [v for (v,) in struct.iter_unpack("!H", values[0])]


def associations(packet, kind):
    """Map each IAID to its lifetimes and bounded nested options."""
    result = {}
    for payload in packet.options(kind):
        assert len(payload) >= 12
        iaid, t1, t2 = struct.unpack_from("!III", payload)
        assert iaid not in result, "Duplicate IAID in one association type"
        result[iaid] = (t1, t2, tlvs(payload[12:]))
    return result


def resources(packet, kind):
    result = set()
    for _, _, children in associations(packet, kind).values():
        for code, data in children:
            if kind == 3 and code == 5:
                assert len(data) >= 24
                result.add(str(ipaddress.IPv6Address(data[:16])))
            elif kind == 25 and code == 26:
                assert len(data) >= 25
                result.add(str(ipaddress.IPv6Network((data[9:25], data[8]), strict=False)))
    return result


def member_ias(packet):
    return {(kind, iaid) for kind in (3, 25) for iaid in associations(packet, kind)}


def unknown_option(trace, packet):
    code = trace.before["unsupported_option_code"]
    evidence(code not in trace.before["supported_option_codes"] and packet.options(code),
             "Expected a well-formed option unsupported by this client")
    progressed(trace, packet)

def require_reconfigure(trace, packet):
    exchanges = [p for p in trace.packets if p.index < packet.index and p.iface == packet.iface]
    evidence(any(p.sport == 546 and p.options(20) for p in exchanges),
             "Reconfigure capability negotiation is missing")
    evidence(any(p.name == "reply" and p.options(11) for p in exchanges),
             "Missing key-distribution Reply")


def bad_checksum(trace, packet):
    # Independent checksum verification on the actual UDP header and payload.
    # This requires ingress capture after offload, not a TX pre-offload capture.
    def folded_sum(data):
        if len(data) % 2:
            data += bytes(1)
        total = sum(v for (v,) in struct.iter_unpack("!H", data))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        return total

    checksums = trace.before["ingress_udp_checksums"]
    control = indexed(trace, "control_index")
    for sample, valid in ((packet, False), (control, True)):
        length = 8 + len(sample.raw)
        checksum = checksums[str(sample.index)]
        pseudo = (ipaddress.IPv6Address(sample.src).packed + ipaddress.IPv6Address(sample.dst).packed
                  + struct.pack("!I3xB", length, 17))
        header = struct.pack("!HHHH", sample.sport, sample.dport, length, checksum)
        evidence((checksum != 0 and folded_sum(pseudo + header + sample.raw) == 65535) == valid,
                 "Expected a bad ingress checksum and a checksum-valid control")
    evidence(control.raw == packet.raw and control.name == packet.name,
             "The checksum control must have identical DHCP payload")


def check_nesting(data, parent=None):
    for code, value in tlvs(data):
        if code in (3, 25):
            assert parent is None and len(value) >= 12
            check_nesting(value[12:], code)
        elif code == 5:
            assert parent == 3 and len(value) >= 24
            check_nesting(value[24:], code)
        elif code == 26:
            assert parent == 25 and len(value) >= 25
            check_nesting(value[25:], code)
        elif code == 13:
            assert len(value) >= 2 and parent in (None, 3, 5, 25, 26)


def caps(packet, code):
    values = packet.options(code)
    evidence(len(values) == 1 and len(values[0]) == 4, "Missing four-octet retransmission cap")
    value = int.from_bytes(values[0], "big")
    evidence(60 <= value <= 86400, "Fixture requires an in-range retransmission cap")
    return value


