"""DNS and stateless-refresh trace checks.

before/after.dns and .domains are ordered lists from the active OS resolver,
scoped to the observed interface. dhcp_dns and dhcp_domains are the DHCP-derived
subset for revocation cases. before/after.link identifies the physical link,
.leases records lease identities, after.alive records DUT process liveness.
after.resolver_changed_at is the monotonic time of the OS update; before.t1_at
is an absolute renewal deadline. All packet times use the same clock.
"""
from ipaddress import IPv6Address
from struct import iter_unpack

from timing_checks import EPS, number, require, response, unchanged_leases


def oro(packet):
    opts = packet.options(6)
    assert len(opts) == 1 and len(opts[0]) % 2 == 0, "expected a well-formed ORO"
    return [v[0] for v in iter_unpack("!H", opts[0])]


def decode_dns(value):
    if not value or len(value) % 16:
        raise ValueError("incomplete IPv6 address list")
    return [str(IPv6Address(value[i:i + 16])) for i in range(0, len(value), 16)]


def decode_domains(value):
    domains = []
    pos = 0
    while pos < len(value):
        labels = []
        while True:
            if pos >= len(value):
                raise ValueError("unterminated search domain")
            length = value[pos]
            pos += 1
            if length == 0:
                break
            if length > 63 or pos + length > len(value):
                raise ValueError("invalid uncompressed label")
            labels.append(value[pos:pos + length].decode("ascii"))
            pos += length
        domains.append(".".join(labels))
    return domains


def updated(trace, name, code, mode):
    attr, decoder = ("dns", decode_dns) if code == 23 else ("domains", decode_domains)
    request = trace.client(name)[0]
    assert code in oro(request)
    reply = response(trace, request)
    values = reply.options(code)
    require(len(values) == 1, "need an unambiguous resolver option")
    expected = decoder(values[0])
    if mode == "multiple":
        require(len(expected) >= 2, "supply at least two resolver entries")
    elif mode in ("replace", "early"):
        require(trace.before[attr] and trace.before[attr] != expected, "start with different resolver data")
    if mode == "early":
        assert reply.time <= trace.after["resolver_changed_at"] < trace.before["t1_at"]
    actual = trace.after[attr]
    if code == 23:
        actual = [str(IPv6Address(a)) for a in actual]
    assert actual == expected, (actual, expected)


def revoked(trace, name, code):
    attr = "dhcp_dns" if code == 23 else "dhcp_domains"
    require(trace.before[attr], "begin with DHCP-sourced resolver settings")
    request = trace.client(name)[0]
    assert code in oro(request)
    reply = response(trace, request)
    require(not reply.options(code), "option must be omitted in the Reply")
    assert not trace.after[attr], "DHCP-sourced option remains installed"


def invalid_resolver(trace, name, code, form):
    req = trace.client(name)[0]
    reply = response(trace, req)
    opts = reply.options(code)
    require(len(opts) == 1, "capture must include the resolver option")
    data = opts[0]
    if isinstance(form, int):
        require(len(data) == form, f"need {form} data octets")
    if form in ("compression", "bad_label", "truncated"):
        # Inspect the offending octet at a label boundary.
        pos = 0
        while pos < len(data) and data[pos] <= 63:
            if pos + 1 + data[pos] > len(data):
                break
            pos += 1 + data[pos]
        if form == "compression":
            require(pos < len(data) and data[pos] >> 6 == 3, "need a compressed name")
        elif form == "bad_label":
            require(pos < len(data) and 64 <= data[pos] < 192, "need a reserved label type")
        else:
            require(pos == len(data) or data[pos] <= 63, "need truncated label or missing terminator")
    decoder = decode_dns if code == 23 else decode_domains
    attr = "dns" if code == 23 else "domains"
    try:
        expected = decoder(data)
    except (UnicodeError, ValueError):
        if form == "valid":
            raise
        assert trace.after[attr] == trace.before[attr], "invalid option changed resolver state"
    else:
        require(form == "valid" or form == 32, "fixture does not contain invalid wire encoding")
        assert trace.after[attr] == expected
    assert trace.after["alive"] is True


def refresh(trace, mode):
    sends = trace.client("information_request")
    reply = response(trace, sends[0])
    if mode == "absent":
        require(not reply.options(32), "option 32 must be absent")
        seconds = 86400
    else:
        seconds = number(reply, 32, 4)
        if mode == "short":
            require(seconds < 600, "supply sub-minimum refresh time")
        elif mode == "infinite":
            require(seconds == 0xffffffff, "supply infinite refresh time")
        else:
            require(600 <= seconds < 0xffffffff, "supply a finite legal refresh time")
        seconds = max(600, seconds)
    if "refresh_max" in trace.before:
        seconds = min(seconds, trace.before["refresh_max"])
    later = [p for p in sends if p.index > reply.index and p.iface == reply.iface]
    if seconds == 0xffffffff:
        require(trace.after["end"] > reply.time + 86400, "short observation of infinite refresh")
        assert not later
    else:
        require(trace.after["end"] >= reply.time + seconds + 1, "observe through refresh deadline")
        assert later, "no scheduled Information-request"
        assert seconds - EPS <= later[0].time - reply.time <= seconds + 1 + EPS


def early_refresh(trace):
    sends = trace.client("information_request")
    require(len(sends) >= 2, "capture the early configuration update")
    first = response(trace, sends[0])
    second = response(trace, sends[1])
    expiry = first.time + max(600, number(first, 32, 4))
    updated_expiry = second.time + max(600, number(second, 32, 4))
    require(second.time < expiry < updated_expiry, "refresh must supersede original deadline")
    require(trace.after["end"] >= expiry + 1, "observe beyond superseded deadline")
    assert all(p.time >= updated_expiry - EPS for p in sends if p.index > second.index)
    opts = second.options(23)
    require(len(opts) == 1, "supply DNS data in the early update")
    assert trace.after["dns"] == decode_dns(opts[0])
