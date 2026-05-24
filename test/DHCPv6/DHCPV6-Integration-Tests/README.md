# DHCPv6 Integration Tests

This folder tracks the IPv6 Ready DHCPv6 conformance integration-test cases from `DHCPv6_Conformance_2_0_0e.pdf`.

Each numbered directory maps to a `DHCP_Conf.x.y.z` test case. Lettered files such as `a.c`, `b.c`, and `c.c` map to the procedure parts in that case. The current files are scaffolds: implement packet setup, execution, observation, and assertions inside the corresponding part file.

`TEST_MANIFEST.csv` lists every scaffolded conformance case and its procedure parts.
