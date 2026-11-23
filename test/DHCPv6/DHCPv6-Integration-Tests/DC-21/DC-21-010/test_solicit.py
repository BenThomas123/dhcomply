from timing_checks import cap_value, EPS, intervals, require


def check(trace):
    source = trace.server("advertise")[-1]
    cap_value(trace, "solicit", "advertise", "valid")
    links = {p.iface for p in trace.client("solicit")} - {source.iface}
    require(len(links) == 1, "record independent second interface")
    other = [p for p in trace.client("solicit") if p.iface in links and p.index > source.index]
    require(len(other) >= 3 and len({p.xid for p in other}) == 1, "record a single capped exchange on B")
    assert all(3240 - EPS <= dt <= 3960 + EPS for dt in intervals(other)[-2:])
