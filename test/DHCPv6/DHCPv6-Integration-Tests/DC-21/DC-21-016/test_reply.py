from resolver_checks import revoked
from lease_clock_checks import resources
from timing_checks import require, response, unchanged_leases


def check(trace):
    revoked(trace, "renew", 23)
    reply = response(trace, trace.client("renew")[0])
    missing = set(trace.before["leases"]) - resources(reply)
    require(any("/" not in binding for binding in missing), "Reply must omit a previously bound address")
    unchanged_leases(trace)
