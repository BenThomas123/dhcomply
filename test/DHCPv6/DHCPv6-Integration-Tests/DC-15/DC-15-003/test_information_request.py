from lease_checks import response


def check(trace):
    p = response(trace, "information_request")
    assert not trace.client("information_request")[0].options(1) and not p.options(1)
    assert trace.after["dns_servers"] == trace.before["offered_dns_servers"] and trace.after["dns_servers"]
