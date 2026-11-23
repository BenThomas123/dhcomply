from lease_checks import bindings, event, leases, response, installed, first_after


def check(trace):
    p = first_after(trace, "wake", "rebind")
    prefixes = {k for k in leases(trace.before) if k[0] == "pd"}
    assert prefixes and prefixes <= bindings(p).keys()
    sleeping = event(trace, "suspend")["time"]
    wake = event(trace, "wake")["time"]
    assert any(r["kind"] == "pd" and sleeping < r["renew_at"] <= wake
               for r in trace.before["timers"])
    installed(trace, response(trace, "rebind"))
