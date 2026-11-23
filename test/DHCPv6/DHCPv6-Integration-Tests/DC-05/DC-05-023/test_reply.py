from lease_checks import bindings, leases


def check(trace):
    p = trace.server("reply")[0]
    keys = {k for k, times in bindings(p).items() if k[0] == "na" and 0 < times[0] < times[1] and p.time + times[0] <= trace.after["time"] < p.time + times[1]}
    assert keys and all(k in leases(trace.after) and k[2] in trace.after["deprecated"] for k in keys)
