from lease_checks import bindings, leases, response


def check(trace):
    p = response(trace, "request")
    records = bindings(p)
    addresses = [k[2] for k in records if k[0] == "na"]
    duplicates = {v for v in addresses if addresses.count(v) > 1}
    assert duplicates
    for addr in duplicates:
        assert trace.after["addresses"].count(addr) == 1
        assert any(k[2] == addr and k in records for k in leases(trace.after))
