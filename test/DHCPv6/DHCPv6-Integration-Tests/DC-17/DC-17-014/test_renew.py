from timing_checks import EPS, require


def check(trace):
    reply = trace.server("reply")[0]
    require(any(len(ia) > 12 and ia[4:12] == bytes(8) for ia in reply.options(3)), "need zero T1/T2 IA_NA")
    renews = [p for p in trace.client("renew") if p.iface == reply.iface and p.index > reply.index]
    assert renews and renews[0].time > reply.time + EPS
    assert all(b.time > a.time for a, b in zip(renews, renews[1:]))
