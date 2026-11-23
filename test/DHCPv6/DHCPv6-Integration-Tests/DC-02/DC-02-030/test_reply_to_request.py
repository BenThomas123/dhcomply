from validation_checks import evidence, exchange, indexed, progressed


def check(trace):
    origin, packet = exchange(trace, "reply", "request")
    control = indexed(trace, "control_index")
    evidence(origin.index < packet.index < control.index and packet.xid != origin.xid
             and control.xid == origin.xid and control.options(1) == origin.options(1),
             "Expected invalid then correlated valid Reply")
    progressed(trace, control)
