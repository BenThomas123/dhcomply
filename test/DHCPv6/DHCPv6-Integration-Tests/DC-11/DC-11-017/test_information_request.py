from timing_checks import require, response
from resolver_checks import decode_dns


def check(trace):
    require(trace.before["link"] != trace.after["link"], "observe attachment to another link")
    sends = trace.client("information_request")
    assert sends[-1].time >= trace.after["link_changed_at"]
    reply = response(trace, sends[-1])
    assert trace.after["dns"] == decode_dns(reply.options(23)[0])
