# DHCPv6 client integration tests

Cases are grouped by DC number, for example `DC-01/DC-01-001/test_solicit.py`. Each `DC-xx-yyy` directory corresponds to one objective in version 0.4 of the supplied catalog. Under `DC-09` (Reply status handling), the `DHCP_Conf.1.3.1-A` through `-G` directories implement the seven Reply-reception parts of the [IPv6 Ready Logo DHCPv6 client specification](https://ipv6ready.org/docs/IPv6_Ready_Test_Specification_DHCPv6_Client_Conformance.pdf). A `test_<variant>.py` file evaluates one message or exchange variant. For example, `test_reply_to_renew.py` checks a Reply in the context of its originating Renew. Sequence tests also inspect prerequisite traffic and the resulting host state.

The Python 3.10+ runner uses the standard library. From this directory:

```sh
python3 -B run.py --list
python3 -B run.py --case DC-02-002 --list
python3 -B run.py --describe DC-21-002
python3 -B run.py --evidence .evidence --case DC-01-001 --message solicit
python3 -B run.py --evidence .evidence --report results.json
```

## Run a real client exchange

The live drivers start the compiled Linux client, create a private multicast-capable dummy interface, and communicate over IPv6 UDP. Run them inside a disposable Linux Docker container started with `--network none` and `NET_ADMIN`. Each scenario starts with a clean DHCP configuration and lease store. The build needs GCC and Make. Cases checking OS address installation also need the client’s runtime commands, including `sudo` and `ip`.

For example, run this from the repository root in Bash. It builds the current checkout, exercises Solicit, saves the captured datagram and reports the verdict. The source mount is read-only.

```sh
suite=test/DHCPv6/DHCPv6-Integration-Tests
mkdir -p "$suite/.evidence"
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE -v "$PWD:/src:ro" -v "$PWD/$suite/.evidence:/results" \
  dhcomply-clion:local sh -ec '
    mkdir /tmp/client
    cp -r /src/src /src/lib /src/Makefile /tmp/client/
    make -s -C /tmp/client -j2
    cd /src/test/DHCPv6/DHCPv6-Integration-Tests
    python3 -B live.py --binary /tmp/client/bin/dhcomply --evidence /results \
      --case DC-01-001 --message solicit
  '
```

Other entry points inside the same kind of container:

| Driver | Exchanges and controls |
| --- | --- |
| `live.py` | Outgoing formation checks for Solicit, Request and Information-request, including fresh exchanges and retransmissions. |
| `discovery_runs.py` | Discovery, timing, DUID and requested-option checks. Use `--list` to see the supported pairs. Supply a fresh evidence directory for each invocation. |
| `live_binding.py` | Successful address grants through a Request or Rapid Commit, and a new discovery after completing a lease. |
| `live_logo.py` | Logo 1.3.1 parts A, B and C. Select with `--part A`, `B` or `C`. Part A observes the Request retry window for more than three minutes. |

Each driver accepts `--binary` and `--evidence`. Capture-based checks cover additional scenarios such as reboot, downstream prefix advertisements, DAD, authenticated Reconfigure, and Logo 1.3.1 parts D–G. Those require a lab that supplies the corresponding stimulus and observations. Use a fresh evidence root for each IA mode, interface configuration, build, or repetition so results remain distinct.

## Bring a lab capture

1. Select the case and message with `run.py --list`. Use `--describe` for the stimulus and expected outcome. Capture traffic before triggering the client and continue through the expected recovery or quiet interval.
2. Record DUT build, case, message, and independent `before` and `after` observations in a JSON object. Use the same clock for packet timestamps, events and snapshots. For a UDP source-port check the snapshots can both be empty. Timing, lease, DNS and authentication checks read additional fields from the lab. See [timing and resolver observations](observation_fields.md) and [lease observations](lease_observations.md). For validation cases, `before.origin_index`, `before.stimulus_index` and, where used, `before.control_index` identify zero-based indices in the merged DHCP capture.
3. Import a classic full-length Ethernet PCAP captured on the DUT link, providing the DUT MAC on that interface. Supply multiple `--link` arguments for synchronized interfaces. For fragmented traffic use an independently reassembled UDP trace and record the fragmentation evidence required by the case.

```sh
python3 -B import_pcap.py --link eth0 02:00:00:00:00:01 lab.pcap \
  --observations observations.json --evidence .evidence
python3 -B run.py --evidence .evidence --case DC-01-001 --message solicit
```

For that example, `observations.json` can contain:

```json
{"case":"DC-01-001","message":"solicit","dut":"dhcomply build under test","before":{},"after":{}}
```

A lab adapter may also write `<evidence>/<case>/<variant>.json` directly. Add a chronological `packets` array to the observation object. Each record contains numeric `time`, interface `iface`, DUT-relative `direction` (`client` for outgoing or `server` for incoming), IPv6 `src` and `dst`, UDP `sport` and `dport`, and the full DHCPv6 UDP `payload` in hexadecimal. For accepted/rejected-response tests preserve the invalid stimulus, corresponding valid control and any host observations the individual check consumes.

## Interpret results

`PASS` and `FAIL` apply to the selected variant and observation window. `INCONCLUSIVE` indicates missing evidence or prerequisites, `N/A` an explicitly inapplicable capability, and `ERROR` an execution or input-format error. Exit status is 0 for a completed selection with at least one pass and no failures or missing evidence, 1 for a failure or error, and 2 for incomplete evidence or an empty applicable selection. Catalog classifications and standards references are preserved in JSON reports. A pass on one mode or build applies only to that run.
