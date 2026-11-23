from lease_checks import response


def check(trace):
    p = response(trace, "information_request")
    assert not p.options(13)
    assert trace.after["dns_servers"] == trace.before["offered_dns_servers"] and trace.after["dns_servers"]
