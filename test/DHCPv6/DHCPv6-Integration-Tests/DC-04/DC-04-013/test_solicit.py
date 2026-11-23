from lease_checks import duid, event, first_after


def check(trace):
    event(trace, "identity_file_corrupted")
    p = first_after(trace, "restart", "solicit")
    assert duid(p).hex() not in trace.before["peer_duids"]
    assert trace.after["diagnostics"] and trace.after["client_alive"]
