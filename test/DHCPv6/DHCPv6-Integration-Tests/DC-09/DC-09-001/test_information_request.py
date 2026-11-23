from lease_checks import response, status


def check(trace):
    p = response(trace, "information_request")
    assert status(p) == 0
    assert trace.after["dns_servers"] == trace.before["offered_dns_servers"] and trace.after["dns_servers"]
