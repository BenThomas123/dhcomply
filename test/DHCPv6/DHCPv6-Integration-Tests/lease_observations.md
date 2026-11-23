# Lease and server-selection capture fields

Sections DC-04 through DC-09, DC-14 through DC-16, and DC-18 through DC-20 read packets and host observations. Supply the fields used by the selected message file. Collect clock values and packet timestamps on the same time scale. Repeat the run with each applicable IA configuration, status, or policy requested by the scenario.

| Fields | Evidence |
| --- | --- |
| `before.leases`, `after.leases` | List of records with `kind` (`na` or `pd`), integer `iaid`, canonical IPv6 `resource` (address or prefix), and absolute `preferred_until` and `valid_until` in seconds. Use JSON null for infinity. |
| `timers`, `time` | Timer rows with kind, iaid, absolute renew_at and rebind_at. Snapshot time is in seconds. |
| `after.events` | Ordered event records with kind, time, and optional resource. Record process restart, reboot, reconnect, link change, suspend, wake, address removal/use, DAD success/failure, and RA emission as applicable. A downstream_ra records iface, subnet, delegated parent prefix, preferred and valid seconds. A link_local_changed event records old and new addresses. |
| `addresses`, `prefixes`, `deprecated`, `dns_servers`, `routes`, `diagnostics` | Lists from OS/client state. Record all configured addresses, routed or delegated prefixes, deprecated addresses, active resolver addresses, installed routes and relevant process log lines respectively. |
| `client_duid`, `server_duid`, `identity_present`, `peer_duids` | Identity store, selected server and independent peers. Encode DUIDs as hexadecimal strings. |
| `configured_iaids`, `configured_ia_counts`, `ia_kinds`, `resource_hints`, `wire_vectors` | Independent scenario configuration. IA mappings use keys na and pd. Wire vectors are rows of [iaid, resource, preferred_seconds, valid_seconds]. |
| `known_duid_vector`, `client_duid_vector`, `server_duid_vector` | Known DUIDs for identity-format or supported length boundary runs. |
| `release_targets`, `offered_dns_servers`, `upstream`, `downstream`, `new_link_configuration` | Independent fixture settings specifying which resources to relinquish, which resolver addresses were offered, or which configuration belongs on the new link. |
| `first_rt`, `retry_windows`, `retry_window`, `confirm_timeout`, `tolerance`, `selection_window`, `release_transmission_limit` | Independent timing profile. Durations are seconds, retry_windows contains inclusive [min,max] pairs, and release_transmission_limit is a packet count. Observe silence through the configured window. |
| `minimum_retry_interval`, `maximum_retry_duration`, `minimum_refresh_interval`, `confirm_retry_min`, `confirm_retry_max` | Timing limits from the configured scheduling profile. |
| `injected_status`, `unknown_option_code`, `unassigned_status_code`, `failed_ia_kind`, `invalid_lease` | Actual stimulus. An invalid lease is a [kind, iaid, resource] key. |
| `policy_selected_server`, `offer_is_selectable`, `expected_resources_after_status`, `expected_followup_messages` | Independent selection and recovery policy for the particular scenario. Derive these before the run from the server configuration and applicable behavior. The verdict compares them with actual captured traffic and client state. |
| `damaged_identifier_code`, `identifier_length_offset`, `outstanding_message`, `outstanding_exchanges` | Capture metadata for identifier and correlation checks. The offset indexes the raw UDP payload. |
| `client_alive`, `reconfigure_accept`, `link_local`, `sol_max_rt`, `inf_max_rt` | Observed process liveness, Reconfigure opt-in, interface address, and applicable retransmission limits from client state. |
