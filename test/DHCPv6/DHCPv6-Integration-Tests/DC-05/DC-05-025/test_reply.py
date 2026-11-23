from lease_checks import bindings, no_use


def check(trace):
    p = trace.server("reply")[0]
    keys = {k for k, times in bindings(p).items() if k[0] == "pd" and 0 < times[1] and p.time + times[1] <= trace.after["time"]}
    no_use(trace, keys)
