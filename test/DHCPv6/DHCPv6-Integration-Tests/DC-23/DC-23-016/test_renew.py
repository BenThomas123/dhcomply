from validation_checks import evidence


def check(trace):
    renew = trace.client("renew")[0]
    before, after = trace.before["per_interface"], trace.after["per_interface"]
    other = trace.before["unaffected_interface"]
    evidence(other != renew.iface and all(before[i]["leases"] and before[i]["dns_servers"]
                                          for i in (other, renew.iface)), "Need two configured interfaces")
    evidence(before[other] != before[renew.iface], "Need distinguishable server data")
    assert after[other] == before[other], "Renew changed the other interface"
    assert any(p.iface == renew.iface and p.xid == renew.xid and p.index > renew.index
               for p in trace.server("reply"))
