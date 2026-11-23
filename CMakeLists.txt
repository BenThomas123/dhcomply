cmake_minimum_required(VERSION 3.20)
project(dhcomply LANGUAGES C)

include(CTest)
if(BUILD_TESTING)
    enable_language(CXX)
    find_package(GTest 1.12 CONFIG QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.17.0
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(googletest)
    endif()

    option(DHCOMPLY_ENABLE_COVERAGE "Collect GCC coverage for the C sources" OFF)
    add_library(dhcomply_core STATIC
        src/dhcomplyBuildMessageFunctions.c
        src/dhcomplyDHCPv6Functions.c
        src/dhcomplyLifeCycle.c
        src/dhcomplyParseMessageFunctions.c
        src/dhcomplySendMessageFunctions.c
        src/dhcomplyStandardLibrary.c
        lib/cJSON.c
    )
    set_target_properties(dhcomply_core PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
    target_include_directories(dhcomply_core PUBLIC src lib)
    target_link_libraries(dhcomply_core PUBLIC m)

    include(GoogleTest)
    function(add_dhcomply_test target)
        add_executable(${target} test/DHCPv6/DHCPv6-Unit-Tests/src/${target}.cpp)
        target_compile_features(${target} PRIVATE cxx_std_17)
        target_link_libraries(${target} PRIVATE dhcomply_core GTest::gtest_main)
        foreach(symbol IN LISTS ARGN)
            target_link_options(${target} PRIVATE "LINKER:--wrap=${symbol}")
        endforeach()
        if(DHCOMPLY_ENABLE_COVERAGE)
            target_link_options(${target} PRIVATE --coverage)
        endif()
        gtest_discover_tests(${target} PROPERTIES TIMEOUT 15 LABELS ${target})
    endfunction()

    if(DHCOMPLY_ENABLE_COVERAGE)
        target_compile_options(dhcomply_core PRIVATE --coverage)
    endif()

    add_dhcomply_test(dhcomplyBuildMessageFunctionsTest
        get_mac_address readLease unpredictable_random
    )
    add_dhcomply_test(dhcomplyDHCPv6FunctionsTest
        access bind close fopen fork getrandom if_nametoindex readlink recv remove select sendto socket usleep waitpid
        malloc realloc inet_ntop execl execlp execv execvp _exit snprintf
    )
    if(DHCOMPLY_ENABLE_COVERAGE)
        target_compile_definitions(dhcomplyDHCPv6FunctionsTest PRIVATE DHCOMPLY_ENABLE_COVERAGE)
    endif()
    add_dhcomply_test(dhcomplyLifeCycleTest
        bind buildSolicit sendSolicit unpredictable_random check_for_advertisement
        parseAdvertisement get_option_index buildRequest sendRequest check_for_message parseReply waitToRetransmit
        check_for_rapid_commit_message check_dad_failure leaseFileExists socket usleep sleep close time buildConfirm
        copyLeaseFileToConfirmTemp delete_lease_file moveConfirmTempLeaseFile sendConfirm buildRelease sendRelease
        remove_message_addresses buildInformationRequest sendInformationRequest parseStatelessReply
        send_dhcpv6_multicast_packet buildRenew sendRenew buildRebind sendRebind
        buildDecline sendDecline is_matching_reply
    )
    add_library(dhcomply_main_for_test OBJECT src/dhcomplyMain.c)
    set_target_properties(dhcomply_main_for_test PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
    target_compile_definitions(dhcomply_main_for_test PRIVATE main=dhcomply_program_main)
    target_link_libraries(dhcomply_main_for_test PRIVATE dhcomply_core)
    if(DHCOMPLY_ENABLE_COVERAGE)
        target_compile_options(dhcomply_main_for_test PRIVATE --coverage)
    endif()
    add_dhcomply_test(dhcomplyMainTest
        init_dhcomply read_config_file leaseFileExists releaseLifeCycle confirmLifeCycle usleep socket
        valid_socket bind_dhcpv6_client_socket close statefulLifeCycleRapidCommit statefulLifeCycle statelessLifeCycle
    )
    target_link_libraries(dhcomplyMainTest PRIVATE dhcomply_main_for_test)
    add_dhcomply_test(dhcomplyParseMessageFunctionsTest execute_formatted_command writeLease append_ipv6_address_if_unique)
    add_dhcomply_test(dhcomplySendMessageFunctionsTest send_dhcpv6_multicast_packet)
    add_dhcomply_test(dhcomplyStandardLibraryTest
        access fopen rename remove fseek ftell fread fwrite ferror malloc calloc strdup inet_ntop getrandom socket
    )
    add_dhcomply_test(checkDadTest)
    target_compile_definitions(checkDadTest PRIVATE DHCOMPLY_DAD_SCRIPT="${PROJECT_SOURCE_DIR}/src/check_dad.sh")
endif()
