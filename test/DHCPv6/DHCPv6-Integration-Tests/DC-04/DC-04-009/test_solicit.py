from lease_checks import bindings, duid


def check(trace):
    packets = trace.client("solicit")
    first, second = packets[0], packets[-1]
    assert any(first.index < p.index < second.index and bindings(p)
               for p in trace.server("reply")), "Expected completed acquisition between Solicit exchanges"
    assert duid(first) == duid(second)
