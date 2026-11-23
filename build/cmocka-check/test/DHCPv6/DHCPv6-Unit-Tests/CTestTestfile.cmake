# CMake generated Testfile for 
# Source directory: C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests
# Build directory: C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[transaction_id_network_order]=] "C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests/dhcpv6_unit_tests.exe" "transaction_id_network_order")
set_tests_properties([=[transaction_id_network_order]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;21;add_test;C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;0;")
add_test([=[option_index_accounts_for_identity_associations]=] "C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests/dhcpv6_unit_tests.exe" "option_index_accounts_for_identity_associations")
set_tests_properties([=[option_index_accounts_for_identity_associations]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;22;add_test;C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;0;")
add_test([=[matching_reply_requires_both_identifiers]=] "C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests/dhcpv6_unit_tests.exe" "matching_reply_requires_both_identifiers")
set_tests_properties([=[matching_reply_requires_both_identifiers]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;23;add_test;C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;0;")
add_test([=[ipv6_round_trip]=] "C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests/dhcpv6_unit_tests.exe" "ipv6_round_trip")
set_tests_properties([=[ipv6_round_trip]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;24;add_test;C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;0;")
add_test([=[trim_whitespace]=] "C:/Users/bent2/usefulStuff/dhcomply/build/cmocka-check/test/DHCPv6/DHCPv6-Unit-Tests/dhcpv6_unit_tests.exe" "trim_whitespace")
set_tests_properties([=[trim_whitespace]=] PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;25;add_test;C:/Users/bent2/usefulStuff/dhcomply/test/DHCPv6/DHCPv6-Unit-Tests/CMakeLists.txt;0;")
subdirs("../../../_deps/cmocka-build")
