# Timing, resolver, and Reconfigure observations

These fields extend the capture JSON for DC-03, DC-11, DC-12, DC-17, DC-21 and DC-22. Each case reads the subset used by its message file and shared check. Record observations from the running client, packet capture, scheduler or operating system. A missing required snapshot field yields `INCONCLUSIVE`. Input capture windows should isolate the intended stimulus and include all client and server traffic on the affected links.

## Clocks and retries

Use seconds on a common monotonic timeline for packet timestamps, deadlines and observation windows. For long scenarios, drive a controlled DUT clock and record packets on that same time scale.

| Field | Source and meaning |
| --- | --- |
| `before.start` | Time of the exchange trigger, including any initial delay. For Elapsed Time cases use the start of elapsed-time accounting. |
| `after.end` | End of continuous observation, including any silent period after the last packet. |
| `before.t1_at`, `before.t2_at`, `before.expiry_at` | Absolute deadlines derived independently from the lease Reply and installation time. |
| `before.expiry_by_resource` | Map of canonical IPv6 address/prefix strings to absolute expirations. |
| `before.random_factors` | Ordered signed RAND fractions delivered by the deterministic scheduler, one per measured retry interval. |
| `before.observe_retries` | Observation horizon in retries, greater than ten for the unlimited-retry example. |
| `before.previous_cap` | Previously effective MRT in seconds. Defaults to 3600 for an unconfigured link. |
| `before.effective_mrt_seconds` | The enabled, accepted cap under test. Compare the actual retry schedule with this independent configured value. |
| `before.request_recovery` | Selected policy, one of `restart`, `alternate`, or `stop`. |
| `before.bucket_capacity`, `before.bucket_per_second`, `before.busy_iface` | Configured token-bucket burst capacity, refill rate and name of stressed interface. Rate-profile cases assume the DUT advertises this policy. |
| `before.leases`, `after.leases` | Installed lease identities, as canonical address/prefix lists in stable order, excluding decrementing timers. |
| `after.shutdown_at`, `after.unusable_at` | Observed shutdown time and time released resources became unusable. |
| `before/after.rfc3339_wall_seconds`, `before/after.monotonic`, `before/after.remaining_seconds` | Numeric wall time (Unix seconds), monotonic time, and remaining lifetime for the same tracked binding around a wall-clock jump. |

## Resolver and link state

Provide ordered `before/after.dns` and `before/after.domains` lists from the OS resolver on the interface under test. Use `before/after.dhcp_dns` and `before/after.dhcp_domains` where a revocation case needs DHCP-specific provenance. For refresh cases disable unrelated refresh triggers. Set `before.refresh_max` only if the DUT actually has a configured upper bound. For early application record `after.resolver_changed_at`. For attachment changes record `before.link`, `after.link` and `after.link_changed_at`. Where used, `before.requested_options` is the list of configured option codes and `after.alive` is an observed process-liveness Boolean.

## Reconfigure

Record `before.reconfigure_accept` when testing the configured acceptance policy. `before.associations` maps interface names to maps of server DUID hex strings. Each entry contains a `client_duid` hex string, `rkap_key` hex string and integer `last_replay` from before the stimulus. Only use disposable test keys. An empty map records absence of an association. Where applicable, setting `before.rkap_supported` to `false` records that the optional RKAP capability is unavailable. `before.observation_seconds` defines a quiet response window measured through `after.end`. Event logging cases read `after.log_lines` as a list of process log strings.
