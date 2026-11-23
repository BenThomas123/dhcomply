from validation_checks import bare_control, exchange, unknown_option


def check(trace):
    origin, packet = exchange(trace, "advertise")
    bare_control(trace, origin, packet, trace.before["unsupported_option_code"])
    unknown_option(trace, packet)
