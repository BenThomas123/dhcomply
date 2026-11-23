from timing_checks import require, schedule


def check(trace):
    cap = trace.before["effective_mrt_seconds"]
    require(60 <= cap <= 86400, "supply an accepted cap within wire limits")
    schedule(trace, "solicit", "configured")
