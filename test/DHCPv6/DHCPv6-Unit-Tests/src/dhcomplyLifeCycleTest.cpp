#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <vector>

extern "C" {
#include "dhcomplyLifeCycle.h"

int __real_close(int fd);
int __real_socket(int family, int type, int protocol);
int __real_bind(int fd, const struct sockaddr *address, socklen_t length);
int __real_usleep(useconds_t duration);
unsigned int __real_sleep(unsigned int seconds);
time_t __real_time(time_t *result);
}

namespace {
enum class Event { copy_lease, delete_lease, open_socket, bind_socket, restore_lease, send, remove_addresses, close_socket };
enum class Reply { accepted, rejected, unavailable };
enum class LeaseEntry { request, rapid_reply, rapid_request, confirm };

struct Transmission {
    uint8_t type;
    uint32_t elapsed;
};

constexpr int client_socket = 546;
constexpr int packet_length = 4;
constexpr int stateless_restart_reached = 73;
constexpr int unexpected_stateless_flow = 74;
constexpr char interface_name[] = "test0";

struct Scenario {
    bool active = false;
    bool socket_fails = false;
    bool dad_fails = false;
    bool reply_has_sol_max_rt = false;
    int advertised_preference = -1;
    uint32_t advertised_sol_max_rt = 0;
    void (*on_stateless_restart)() = nullptr;
    std::vector<unsigned int> refresh_sleeps;
    int refresh_seconds = 0;
    int info_max_rt_seconds = 0;
    int information_builds = 0;
    config_t config = {};
    uint8_t expected_removed_type = RELEASE_MESSAGE_TYPE;
    uint8_t expected_renew_request = REQUEST_MESSAGE_TYPE;
    std::deque<bool> lease_exists;
    std::deque<bool> advertisements;
    std::deque<bool> advertisement_validity;
    std::deque<int> rapid_responses;
    std::deque<bool> response_available;
    std::deque<int> reply_sizes;
    std::deque<bool> stateless_reply_valid;
    std::deque<Reply> replies;
    std::deque<int> bind_errors;
    std::deque<time_t> clock;
    time_t last_time = 1000;
    std::vector<Event> events;
    std::vector<Transmission> transmissions;
    std::vector<uint8_t> reply_requests;
    std::vector<uint64_t> retry_delays;
    std::vector<useconds_t> sleep_delays;
    std::array<dhcpv6_message_t, INFORMATION_REQUEST_MESSAGE_TYPE + 1> messages = {};
    std::array<dhcpv6_option_t, 2> advertisement_options = {};
    std::array<dhcpv6_option_t, 5> lease_options = {};
    std::array<dhcpv6_option_t, 2> stateless_options = {};
    dhcpv6_message_t parsed = {};
};

Scenario scenario;

template <typename T>
T next(std::deque<T> &values, T fallback) {
    if (values.empty()) {
        return fallback;
    }
    T value = values.front();
    values.pop_front();
    return value;
}

dhcpv6_message_t *build(uint8_t type, const config_t *config, const char *interface) {
    if (config) {
        EXPECT_EQ(config, &scenario.config);
    }
    if (interface) {
        EXPECT_STREQ(interface, interface_name);
    }
    return &scenario.messages[type];
}

int send(uint8_t type, dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    EXPECT_EQ(message, &scenario.messages[type]);
    EXPECT_EQ(fd, client_socket);
    EXPECT_STREQ(interface, interface_name);
    scenario.events.push_back(Event::send);
    scenario.transmissions.push_back({type, elapsed});
    return 0;
}

int provide_packet(uint8_t *packet, int fd, uint8_t type, int size = packet_length) {
    EXPECT_EQ(fd, client_socket);
    EXPECT_NE(packet, nullptr);
    packet[0] = type;
    packet[1] = type ? size : 0;
    return packet[1];
}

class LifeCycleTest : public testing::Test {
protected:
    char interface[sizeof(interface_name)] = "test0";
    char mode[3] = "N";

    void SetUp() override {
        scenario = {};
        scenario.active = true;
        for (size_t type = 1; type < scenario.messages.size(); ++type) {
            scenario.messages[type].message_type = static_cast<uint8_t>(type);
        }
        scenario.lease_options[0].option_code = IA_NA_OPTION_CODE;
        scenario.lease_options[0].ia_na_t.t1 = 60;
        scenario.lease_options[0].ia_na_t.t2 = 90;
        scenario.lease_options[1].option_code = IA_ADDR_OPTION_CODE;
        scenario.lease_options[1].ia_address_t.valid_lifetime = 120;
        scenario.lease_options[2].option_code = IA_PD_OPTION_CODE;
        scenario.lease_options[2].ia_pd_t.t1 = 30;
        scenario.lease_options[2].ia_pd_t.t2 = 90;
        scenario.lease_options[3].option_code = IAPREFIX_OPTION_CODE;
        scenario.lease_options[3].ia_prefix_t.valid_lifetime = 120;
    }

    void TearDown() override { scenario = {}; }

    void expect_on_stateless_restart(void (*check)()) {
        scenario.on_stateless_restart = check;
        EXPECT_EXIT({
            statelessLifeCycle(&scenario.config, interface, client_socket);
            std::exit(unexpected_stateless_flow);
        }, testing::ExitedWithCode(stateless_restart_reached), "");
    }

    std::vector<uint8_t> transmitted_types() {
        std::vector<uint8_t> types;
        for (const auto &packet : scenario.transmissions) {
            types.push_back(packet.type);
        }
        return types;
    }
};

using LifeCycleDeathTest = LifeCycleTest;

class LeaseProgressionTest : public LifeCycleTest, public testing::WithParamInterface<LeaseEntry> {
protected:
    void SetUp() override {
        LifeCycleTest::SetUp();
        if (GetParam() == LeaseEntry::confirm) {
            scenario.expected_renew_request = CONFIRM_MESSAGE_TYPE;
        } else if (GetParam() == LeaseEntry::rapid_reply) {
            scenario.expected_renew_request = SOLICIT_MESSAGE_TYPE;
        }
    }

    int run_with_lease() {
        scenario.replies.push_front(Reply::accepted);
        if (GetParam() == LeaseEntry::rapid_reply) {
            scenario.rapid_responses = {REPLY_MESSAGE_TYPE};
        } else {
            scenario.response_available.push_front(true);
        }

        switch (GetParam()) {
            case LeaseEntry::request:
                scenario.advertisements = {true};
                statefulLifeCycle(&scenario.config, interface, client_socket, mode);
                return 0;
            case LeaseEntry::rapid_request:
                scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
                statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
                return 0;
            case LeaseEntry::rapid_reply:
                statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
                return 0;
            case LeaseEntry::confirm:
                scenario.lease_exists.push_front(true);
                return confirmLifeCycle(&scenario.config, interface);
        }
        return 1;
    }

    std::vector<uint8_t> entry_packets() {
        if (GetParam() == LeaseEntry::confirm) {
            return {CONFIRM_MESSAGE_TYPE};
        }
        if (GetParam() == LeaseEntry::rapid_reply) {
            return {SOLICIT_MESSAGE_TYPE};
        }
        return {SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE};
    }
};

class StatefulLeaseProgressionTest : public LeaseProgressionTest {};

class AdvertisementTimingTest : public LifeCycleTest, public testing::WithParamInterface<bool> {
protected:
    void receive_advertisement(uint8_t preference, size_t misses, bool reject_first = false) {
        scenario.advertised_preference = preference;
        scenario.advertised_sol_max_rt = 60;
        scenario.response_available = {true};
        scenario.replies = {Reply::accepted};
        if (reject_first) {
            scenario.advertisement_validity = {false, true};
        }
        if (GetParam()) {
            scenario.rapid_responses.assign(misses, 0);
            if (reject_first) {
                scenario.rapid_responses.push_back(ADVERTISE_MESSAGE_TYPE);
            }
            scenario.rapid_responses.push_back(ADVERTISE_MESSAGE_TYPE);
            statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
        } else {
            scenario.advertisements.assign(misses, false);
            if (reject_first) {
                scenario.advertisements.push_back(true);
            }
            scenario.advertisements.push_back(true);
            statefulLifeCycle(&scenario.config, interface, client_socket, mode);
        }
    }
};

const char *lease_entry_name(const testing::TestParamInfo<LeaseEntry> &info) {
    switch (info.param) {
        case LeaseEntry::request: return "Request";
        case LeaseEntry::rapid_reply: return "RapidReply";
        case LeaseEntry::rapid_request: return "RapidRequest";
        case LeaseEntry::confirm: return "Confirm";
    }
    return "Unknown";
}
}

extern "C" {
int __wrap_socket(int family, int type, int protocol) {
    if (!scenario.active) {
        return __real_socket(family, type, protocol);
    }
    EXPECT_EQ(family, AF_INET6);
    EXPECT_EQ(type, SOCK_DGRAM);
    EXPECT_EQ(protocol, IPPROTO_UDP);
    scenario.events.push_back(Event::open_socket);
    if (scenario.socket_fails) {
        errno = EMFILE;
        return -1;
    }
    return client_socket;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (!scenario.active || fd != client_socket) {
        return __real_bind(fd, address, length);
    }
    scenario.events.push_back(Event::bind_socket);
    if (int error = next(scenario.bind_errors, 0)) {
        errno = error;
        return -1;
    }
    return 0;
}

int __wrap_close(int fd) {
    if (!scenario.active || fd != client_socket) {
        return __real_close(fd);
    }
    scenario.events.push_back(Event::close_socket);
    return 0;
}

int __wrap_usleep(useconds_t duration) {
    if (!scenario.active) {
        return __real_usleep(duration);
    }
    scenario.sleep_delays.push_back(duration);
    return 0;
}

unsigned int __wrap_sleep(unsigned int seconds) {
    if (!scenario.active) {
        return __real_sleep(seconds);
    }
    scenario.refresh_sleeps.push_back(seconds);
    return 0;
}

time_t __wrap_time(time_t *result) {
    if (!scenario.active) {
        return __real_time(result);
    }
    scenario.last_time = next(scenario.clock, scenario.last_time);
    if (result) {
        *result = scenario.last_time;
    }
    return scenario.last_time;
}

uint32_t __wrap_unpredictable_random(void) { return 0; }

void __wrap_waitToRetransmit(uint64_t delay) {
    scenario.retry_delays.push_back(delay);
}

bool __wrap_leaseFileExists(const char *interface) {
    EXPECT_STREQ(interface, interface_name);
    return next(scenario.lease_exists, false);
}

int __wrap_copyLeaseFileToConfirmTemp(const char *interface) {
    EXPECT_STREQ(interface, interface_name);
    scenario.events.push_back(Event::copy_lease);
    return 0;
}

void __wrap_delete_lease_file(char *interface) {
    EXPECT_STREQ(interface, interface_name);
    scenario.events.push_back(Event::delete_lease);
}

int __wrap_moveConfirmTempLeaseFile(const char *interface) {
    EXPECT_STREQ(interface, interface_name);
    scenario.events.push_back(Event::restore_lease);
    return 0;
}

void __wrap_remove_message_addresses(dhcpv6_message_t *message, const char *interface) {
    EXPECT_EQ(message, &scenario.messages[scenario.expected_removed_type]);
    EXPECT_STREQ(interface, interface_name);
    scenario.events.push_back(Event::remove_addresses);
}

bool __wrap_check_dad_failure(const char *interface) {
    EXPECT_STREQ(interface, interface_name);
    return scenario.dad_fails;
}

bool __wrap_is_matching_reply(uint8_t *packet, int size, dhcpv6_message_t *request) {
    EXPECT_EQ(request, &scenario.messages[DECLINE_MESSAGE_TYPE]);
    return size == packet_length && packet[0] == REPLY_MESSAGE_TYPE;
}

int __wrap_check_for_advertisement(int fd, uint8_t *packet, const config_t *config) {
    EXPECT_EQ(config, &scenario.config);
    return provide_packet(packet, fd, next(scenario.advertisements, false) ? ADVERTISE_MESSAGE_TYPE : 0);
}

int __wrap_check_for_rapid_commit_message(int fd, uint8_t *packet, int *type) {
    *type = next(scenario.rapid_responses, 0);
    return provide_packet(packet, fd, static_cast<uint8_t>(*type));
}

int __wrap_check_for_message(int fd, uint8_t *packet, int type) {
    EXPECT_EQ(type, REPLY_MESSAGE_TYPE);
    if (!next(scenario.response_available, false)) {
        return provide_packet(packet, fd, 0);
    }
    return provide_packet(packet, fd, REPLY_MESSAGE_TYPE, next(scenario.reply_sizes, packet_length));
}

int __wrap_get_option_index(uint8_t *packet, unsigned long int size, uint8_t code) {
    if (size == packet_length && packet[0] == ADVERTISE_MESSAGE_TYPE) {
        if (code == PREFERENCE_OPTION_CODE && scenario.advertised_preference >= 0) {
            return 0;
        }
        if (code == SOL_MAX_RT_OPTION_CODE && scenario.advertised_sol_max_rt) {
            return 1;
        }
    }
    if (size >= packet_length && packet[0] == REPLY_MESSAGE_TYPE) {
        if (code == SOL_MAX_RT_OPTION_CODE && scenario.reply_has_sol_max_rt) {
            return 4;
        }
        if (code == IA_NA_OPTION_CODE || (code == INFORMATION_REFRESH_OPTION_CODE && scenario.refresh_seconds)) {
            return 0;
        }
        if (code == INF_MAX_RT_OPTION_CODE && scenario.info_max_rt_seconds) {
            return 1;
        }
        if (code == IA_PD_OPTION_CODE) {
            return 2;
        }
    }
    return -1;
}

dhcpv6_message_t *__wrap_parseAdvertisement(uint8_t *packet, dhcpv6_message_t *request, int size) {
    EXPECT_EQ(request, &scenario.messages[SOLICIT_MESSAGE_TYPE]);
    EXPECT_EQ(size, packet[0] == ADVERTISE_MESSAGE_TYPE ? packet_length : 0);
    auto &message = scenario.messages[ADVERTISE_MESSAGE_TYPE];
    scenario.advertisement_options[0].option_code = PREFERENCE_OPTION_CODE;
    scenario.advertisement_options[0].preference_t.preference_value = scenario.advertised_preference;
    scenario.advertisement_options[1].option_code = SOL_MAX_RT_OPTION_CODE;
    scenario.advertisement_options[1].SOL_MAX_RT_t.SOL_MAX_RT_value = scenario.advertised_sol_max_rt;
    message.option_list = scenario.advertisement_options.data();
    message.option_count = scenario.advertisement_options.size();
    message.valid = size == packet_length && next(scenario.advertisement_validity, true);
    return &message;
}

dhcpv6_message_t *__wrap_parseReply(uint8_t *packet, dhcpv6_message_t *request, const char *interface, int size) {
    EXPECT_EQ(packet[0], REPLY_MESSAGE_TYPE);
    EXPECT_EQ(size, packet[1]);
    EXPECT_STREQ(interface, interface_name);
    scenario.reply_requests.push_back(request->message_type);
    Reply result = next(scenario.replies, Reply::unavailable);
    if (result == Reply::unavailable) {
        return nullptr;
    }
    scenario.parsed.valid = result == Reply::accepted;
    scenario.lease_options[4].option_code = SOL_MAX_RT_OPTION_CODE;
    scenario.lease_options[4].SOL_MAX_RT_t.SOL_MAX_RT_value = 60;
    scenario.parsed.option_list = scenario.lease_options.data();
    scenario.parsed.option_count = scenario.reply_has_sol_max_rt ? 5 : 4;
    return &scenario.parsed;
}

dhcpv6_message_t *__wrap_parseStatelessReply(uint8_t *packet, dhcpv6_message_t *request, const char *interface,
                                            int size) {
    EXPECT_EQ(size, packet[0] == REPLY_MESSAGE_TYPE ? packet_length : 0);
    EXPECT_STREQ(interface, interface_name);
    EXPECT_EQ(request, &scenario.messages[INFORMATION_REQUEST_MESSAGE_TYPE]);
    scenario.reply_requests.push_back(request->message_type);
    auto &refresh = scenario.stateless_options[0];
    refresh.option_code = INFORMATION_REFRESH_OPTION_CODE;
    refresh.information_refresh_time_t.information_refresh_time = scenario.refresh_seconds;
    auto &max_rt = scenario.stateless_options[1];
    max_rt.option_code = INF_MAX_RT_OPTION_CODE;
    max_rt.INF_MAX_RT_t.INF_MAX_RT_value = scenario.info_max_rt_seconds;
    scenario.parsed.option_list = scenario.stateless_options.data();
    scenario.parsed.option_count = scenario.stateless_options.size();
    scenario.parsed.valid = size == packet_length && next(scenario.stateless_reply_valid, true);
    return &scenario.parsed;
}

dhcpv6_message_t *__wrap_buildSolicit(config_t *config, const char *interface) {
    return build(SOLICIT_MESSAGE_TYPE, config, interface);
}

dhcpv6_message_t *__wrap_buildRequest(dhcpv6_message_t *advertisement, config_t *config) {
    EXPECT_EQ(advertisement, &scenario.messages[ADVERTISE_MESSAGE_TYPE]);
    return build(REQUEST_MESSAGE_TYPE, config, nullptr);
}

dhcpv6_message_t *__wrap_buildRenew(dhcpv6_message_t *reply, dhcpv6_message_t *request, config_t *config) {
    EXPECT_EQ(reply, &scenario.parsed);
    EXPECT_EQ(request, &scenario.messages[scenario.expected_renew_request]);
    return build(RENEW_MESSAGE_TYPE, config, nullptr);
}

dhcpv6_message_t *__wrap_buildRebind(dhcpv6_message_t *reply, config_t *config) {
    EXPECT_EQ(reply, &scenario.parsed);
    return build(REBIND_MESSAGE_TYPE, config, nullptr);
}

dhcpv6_message_t *__wrap_buildConfirm(config_t *config, const char *interface, uint32_t *t1, uint32_t *t2,
                                     uint32_t *lifetime) {
    *t1 = scenario.lease_options[0].ia_na_t.t1;
    *t2 = scenario.lease_options[0].ia_na_t.t2;
    *lifetime = scenario.lease_options[1].ia_address_t.valid_lifetime;
    return build(CONFIRM_MESSAGE_TYPE, config, interface);
}

dhcpv6_message_t *__wrap_buildRelease(config_t *config, const char *interface) {
    return build(RELEASE_MESSAGE_TYPE, config, interface);
}

dhcpv6_message_t *__wrap_buildDecline(dhcpv6_message_t *reply, config_t *config) {
    EXPECT_EQ(reply, &scenario.parsed);
    return build(DECLINE_MESSAGE_TYPE, config, nullptr);
}

dhcpv6_message_t *__wrap_buildInformationRequest(config_t *config, const char *interface) {
    if (++scenario.information_builds > 1) {
        if (!scenario.on_stateless_restart) {
            std::exit(unexpected_stateless_flow);
        }
        scenario.on_stateless_restart();
        std::exit(testing::Test::HasFailure() ? unexpected_stateless_flow : stateless_restart_reached);
    }
    return build(INFORMATION_REQUEST_MESSAGE_TYPE, config, interface);
}

int __wrap_sendSolicit(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(SOLICIT_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendRequest(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(REQUEST_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendRenew(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(RENEW_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendRebind(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(REBIND_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendConfirm(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(CONFIRM_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendRelease(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(RELEASE_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendDecline(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(DECLINE_MESSAGE_TYPE, message, fd, interface, elapsed);
}

int __wrap_sendInformationRequest(dhcpv6_message_t *message, int fd, const char *interface, uint32_t elapsed) {
    return send(INFORMATION_REQUEST_MESSAGE_TYPE, message, fd, interface, elapsed);
}

void __wrap_send_dhcpv6_multicast_packet(int, const uint8_t *, size_t, const char *) {
    ADD_FAILURE() << "Unexpected DHCPv6 transmission in lifecycle test";
}
}

namespace {
TEST_P(AdvertisementTimingTest, DefersRequestAfterLateAdvertisementFromNonPreferredServer) {
    receive_advertisement(90, 7);
    ASSERT_EQ(scenario.transmissions.size(), 9u);
    EXPECT_EQ(scenario.transmissions.back().type, REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{REQUEST_MESSAGE_TYPE});
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{1000000});
}

TEST_P(AdvertisementTimingTest, RequestsImmediatelyAfterMaximumPreferenceAdvertisement) {
    receive_advertisement(255, 7);
    ASSERT_EQ(scenario.transmissions.size(), 9u);
    EXPECT_EQ(scenario.transmissions.back().type, REQUEST_MESSAGE_TYPE);
    EXPECT_TRUE(scenario.sleep_delays.empty());
}

TEST_P(AdvertisementTimingTest, EarlyAdvertisementDoesNotDelayRequest) {
    receive_advertisement(90, 0);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE}));
    EXPECT_TRUE(scenario.sleep_delays.empty());
    EXPECT_TRUE(scenario.retry_delays.empty());
}

TEST_P(AdvertisementTimingTest, IgnoresRejectedAdvertisement) {
    receive_advertisement(255, 0, true);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{
        SOLICIT_MESSAGE_TYPE, SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE
    }));
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{lower_solicit[0]});
}

INSTANTIATE_TEST_SUITE_P(
    SolicitModes, AdvertisementTimingTest, testing::Bool(),
    [](const testing::TestParamInfo<bool> &info) { return info.param ? "RapidCommit" : "Stateful"; });

TEST_F(LifeCycleTest, StatefulIgnoresRejectedReply) {
    scenario.advertisements = {true};
    scenario.response_available = {true, true};
    scenario.replies = {Reply::rejected, Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{REQUEST_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, StatefulStopsAfterParserError) {
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, RapidCommitIgnoresRejectedDirectReply) {
    scenario.rapid_responses = {REPLY_MESSAGE_TYPE, REPLY_MESSAGE_TYPE};
    scenario.replies = {Reply::rejected, Reply::unavailable};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE});
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE, SOLICIT_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, RapidCommitFallbackIgnoresRejectedReply) {
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    scenario.response_available = {true, true};
    scenario.replies = {Reply::rejected, Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{REQUEST_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, RapidCommitFallbackStopsAfterParserError) {
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, RenewReplyStartsANewLeaseTimer) {
    // The first lease reaches T1. The second has just started when the lease is removed.
    scenario.clock = {1000, 1060, 1060, 1060};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, RENEW_MESSAGE_TYPE}));
    EXPECT_TRUE(scenario.retry_delays.empty());
}

TEST_P(LeaseProgressionTest, RenewRetransmitsBeforeAcceptingAReply) {
    scenario.clock = {1000, 1060, 1060, 1060};
    scenario.lease_exists = {true, true, false};
    scenario.response_available = {false, true};
    scenario.reply_sizes = GetParam() == LeaseEntry::rapid_reply
        ? std::deque<int>{12}
        : std::deque<int>{packet_length, 12};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE});
    ASSERT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.transmissions.back().elapsed, renew_lower[0] / 10);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{renew_lower[0]});
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, RENEW_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, LeaseRemovalDuringRenewDelaySkipsRetransmission) {
    scenario.clock = {1000, 1060};
    scenario.lease_exists = {true, false};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{renew_lower[0]});
}

TEST_P(LeaseProgressionTest, LeaseRemovalBeforeRenewDelaySkipsRetransmission) {
    scenario.clock = {1000, 1060};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_TRUE(scenario.retry_delays.empty());
}

TEST_P(LeaseProgressionTest, RebindRetransmitsBeforeAcceptingAReply) {
    scenario.clock = {1000, 1060, 1090, 1090, 1090, 1090, 1090, 1090};
    if (GetParam() == LeaseEntry::confirm) {
        // Confirm checks lease removal in its Renew loop but not in its Rebind loop.
        scenario.lease_exists = {true, true, false};
    } else {
        scenario.lease_exists = {true, true, true, true, false};
    }
    scenario.response_available = {false, false, false, true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    ASSERT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.transmissions.back().elapsed, rebind_lower[0] / 10);
    EXPECT_EQ(scenario.retry_delays, (std::vector<uint64_t>{renew_lower[0], rebind_lower[0]}));
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, REBIND_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, RebindDoesNotRetransmitAfterImmediateReply) {
    scenario.clock = {1000, 1060, 1090};
    scenario.lease_exists = {true, true};
    scenario.response_available = {false, false, true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{renew_lower[0]});
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, REBIND_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, LeaseExpiresBeforeEnteringRebindRetryLoop) {
    scenario.lease_options[0].ia_na_t.t2 = 65;
    scenario.clock = {1000, 1060, 1065, 1119, 1120};
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(LeaseProgressionTest, ExpiryBeforeRebindRetryRemovesAddresses) {
    scenario.lease_options[0].ia_na_t.t2 = 65;
    scenario.clock = {1000, 1060, 1065, 1119, 1120};
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);
    EXPECT_EQ(std::count(scenario.events.begin(), scenario.events.end(), Event::remove_addresses), 1);
}

TEST_P(LeaseProgressionTest, RebindStopsAtItsRetryLimit) {
    scenario.lease_options[0].ia_na_t.t2 = 65;
    scenario.lease_options[1].ia_address_t.valid_lifetime = 7200;
    scenario.clock = {1000, 1060, 1065};
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    if (GetParam() != LeaseEntry::confirm) {
        scenario.lease_exists.assign(2 * REBIND_RETRANS_COUNT, true);
    }
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    expected.insert(expected.end(), REBIND_RETRANS_COUNT + 1, REBIND_MESSAGE_TYPE);
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(LeaseProgressionTest, RebindRetryLimitRemovesAddresses) {
    scenario.lease_options[0].ia_na_t.t2 = 65;
    scenario.lease_options[1].ia_address_t.valid_lifetime = 7200;
    scenario.clock = {1000, 1060, 1065};
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    if (GetParam() != LeaseEntry::confirm) {
        scenario.lease_exists.assign(2 * REBIND_RETRANS_COUNT, true);
    }
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);
    EXPECT_EQ(std::count(scenario.events.begin(), scenario.events.end(), Event::remove_addresses), 1);
}

TEST_P(LeaseProgressionTest, ExpiredLeaseSkipsRebind) {
    scenario.clock = {1000, 1060, 1120, 1120};
    scenario.lease_exists = {true, true};
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE});
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(LeaseProgressionTest, ExpiredLeaseIsDeleted) {
    scenario.clock = {1000, 1060, 1120, 1120};
    scenario.lease_exists = {true, true};
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);
    const auto deletions = std::count(scenario.events.begin(), scenario.events.end(), Event::delete_lease);
    EXPECT_EQ(deletions, GetParam() == LeaseEntry::confirm ? 2 : 1);
}

TEST_P(LeaseProgressionTest, LeaseExpiresWhileWaitingForRebindReply) {
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    scenario.clock = {1000, 1060, 1090, 1090, 1090, 1120};
    scenario.lease_exists = {true, true, true, true};
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(LeaseProgressionTest, ExpiryWhileWaitingForRebindReplyRemovesAddresses) {
    scenario.expected_removed_type = REBIND_MESSAGE_TYPE;
    scenario.clock = {1000, 1060, 1090, 1090, 1090, 1120};
    scenario.lease_exists = {true, true, true, true};
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);
    const auto removals = std::count(scenario.events.begin(), scenario.events.end(), Event::remove_addresses);
    EXPECT_EQ(removals, 1);
}

TEST_P(LeaseProgressionTest, WaitsForT1AsLongAsLeaseExists) {
    scenario.clock = {1000, 1001, 1002};
    scenario.lease_exists = {true, false};
    EXPECT_EQ(run_with_lease(), 0);
    EXPECT_EQ(transmitted_types(), entry_packets());
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{1000});
}

TEST_P(LeaseProgressionTest, WaitsForT2AfterRenewRetriesExhaust) {
    scenario.clock = {1000, 1060, 1070, 1080};
    scenario.lease_exists = {true, true, true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE});
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{1000});
}

TEST_P(LeaseProgressionTest, CapsElapsedTimeOnLateRenewRetransmission) {
    scenario.lease_options[0].ia_na_t.t2 = 2000;
    scenario.lease_options[1].ia_address_t.valid_lifetime = 3000;
    scenario.clock = {1000, 1060};
    scenario.response_available.assign(7, false);
    scenario.response_available.push_back(true);
    scenario.replies = {Reply::accepted};
    scenario.lease_exists.assign(14, true);
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), 8, RENEW_MESSAGE_TYPE);
    ASSERT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.transmissions.back().elapsed, 65535u);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, RENEW_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, CapsElapsedTimeOnLateRebindRetransmission) {
    scenario.lease_options[0].ia_na_t.t2 = 65;
    scenario.lease_options[1].ia_address_t.valid_lifetime = 7200;
    scenario.clock = {1000, 1060, 1065};
    scenario.response_available.assign(8, false);
    scenario.response_available.push_back(true);
    scenario.replies = {Reply::accepted};
    if (GetParam() != LeaseEntry::confirm) {
        scenario.lease_exists.assign(14, true);
    }
    EXPECT_EQ(run_with_lease(), 0);

    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    expected.insert(expected.end(), 8, REBIND_MESSAGE_TYPE);
    ASSERT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.transmissions.back().elapsed, 65535u);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{scenario.expected_renew_request, REBIND_MESSAGE_TYPE}));
}

TEST_P(LeaseProgressionTest, RetriesDeclineWhenDuplicateAddressReplyTimesOut) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.response_available = {false, true};
    scenario.lease_exists = {true, true};
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), {DECLINE_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE});
    const size_t retry_index = expected.size() - 1;
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    ASSERT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.transmissions[retry_index].elapsed, decline_lower[0] / 10);
    ASSERT_FALSE(scenario.retry_delays.empty());
    EXPECT_EQ(scenario.retry_delays.front(), decline_lower[0]);
}

TEST_P(LeaseProgressionTest, DeclineStopsAtItsRetryLimit) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    if (GetParam() != LeaseEntry::confirm) {
        scenario.lease_exists.assign(2 * DECLINE_RETRANS_COUNT, true);
    }
    EXPECT_EQ(run_with_lease(), GetParam() == LeaseEntry::confirm ? 1 : 0);

    auto expected = entry_packets();
    expected.insert(expected.end(), DECLINE_RETRANS_COUNT + 1, DECLINE_MESSAGE_TYPE);
    if (GetParam() != LeaseEntry::confirm) {
        expected.insert(expected.end(), SOLICIT_RETRANS_COUNT + 1, SOLICIT_MESSAGE_TYPE);
    }
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(std::count(scenario.events.begin(), scenario.events.end(), Event::remove_addresses), 1);
}

TEST_P(StatefulLeaseProgressionTest, LeaseRemovalDuringDeclineDelaySkipsRetransmission) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.lease_exists = {true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.push_back(DECLINE_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{decline_lower[0]});
}

TEST_P(StatefulLeaseProgressionTest, WaitsForLifetimeBasedT1WhenServerOmitsTimers) {
    scenario.lease_options[0].ia_na_t.t1 = 0;
    scenario.lease_options[0].ia_na_t.t2 = 0;
    scenario.clock = {1000, 1059, 1060};
    scenario.lease_exists = {true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{1000});
}

TEST_P(StatefulLeaseProgressionTest, AppliesConfiguredTimersWhenServerOmitsThem) {
    scenario.lease_options[0].ia_na_t.t1 = 0;
    scenario.lease_options[0].ia_na_t.t2 = 0;
    scenario.config.t1 = 35;
    scenario.config.t2 = 45;
    scenario.clock = {1000, 1034, 1035, 1044};
    scenario.lease_exists = {true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{1000});
}

TEST_P(StatefulLeaseProgressionTest, RenewsPrefixOnlyLeaseAtItsT1) {
    std::strcpy(mode, "P");
    scenario.clock = {1000, 1030};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(StatefulLeaseProgressionTest, UsesEarliestT1ForCombinedLease) {
    std::strcpy(mode, "NP");
    scenario.clock = {1000, 1030};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.push_back(RENEW_MESSAGE_TYPE);
    EXPECT_EQ(transmitted_types(), expected);
}

TEST_P(StatefulLeaseProgressionTest, LeaseRemovalBeforeRebindDelaySkipsRetransmission) {
    scenario.clock = {1000, 1060, 1090};
    scenario.lease_exists = {true, true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{renew_lower[0]});
}

TEST_P(StatefulLeaseProgressionTest, LeaseRemovalDuringRebindDelaySkipsRetransmission) {
    scenario.clock = {1000, 1060, 1090};
    scenario.lease_exists = {true, true, true, false};
    EXPECT_EQ(run_with_lease(), 0);
    auto expected = entry_packets();
    expected.insert(expected.end(), {RENEW_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, REBIND_MESSAGE_TYPE});
    EXPECT_EQ(transmitted_types(), expected);
    EXPECT_EQ(scenario.retry_delays, (std::vector<uint64_t>{renew_lower[0], rebind_lower[0]}));
}

INSTANTIATE_TEST_SUITE_P(
    LeaseAcquisition, LeaseProgressionTest,
    testing::Values(LeaseEntry::request, LeaseEntry::rapid_reply, LeaseEntry::rapid_request, LeaseEntry::confirm),
    lease_entry_name);

INSTANTIATE_TEST_SUITE_P(
    StatefulLeaseAcquisition, StatefulLeaseProgressionTest,
    testing::Values(LeaseEntry::request, LeaseEntry::rapid_reply, LeaseEntry::rapid_request), lease_entry_name);

TEST_F(LifeCycleTest, StatefulRequestsLeaseAfterAdvertisement) {
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), 2u);
    EXPECT_EQ(scenario.transmissions[0].type, SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[1].type, REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{REQUEST_MESSAGE_TYPE});
}

TEST_F(LifeCycleTest, StatefulStartsEachNewExchangeWithZeroElapsedTime) {
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), 2u);
    EXPECT_EQ(scenario.transmissions[0].elapsed, 0u);
    EXPECT_EQ(scenario.transmissions[1].elapsed, 0u);
}

TEST_F(LifeCycleTest, StatefulSkipsRetryDelayOnImmediateAdvertisement) {
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_TRUE(scenario.retry_delays.empty());
}

TEST_F(LifeCycleTest, StatefulRetriesSolicitWhenNoServerAnswers) {
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), SOLICIT_RETRANS_COUNT + 1u);
    ASSERT_EQ(scenario.retry_delays.size(), SOLICIT_RETRANS_COUNT);
    for (const auto &packet : scenario.transmissions) {
        EXPECT_EQ(packet.type, SOLICIT_MESSAGE_TYPE);
    }
}

TEST_F(LifeCycleTest, StatefulUpdatesElapsedTimeOnSolicitRetry) {
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), SOLICIT_RETRANS_COUNT + 1u);
    EXPECT_EQ(scenario.transmissions[0].elapsed, 0u);
    EXPECT_EQ(scenario.transmissions[1].elapsed, lower_solicit[0] / 10);
}

TEST_F(LifeCycleTest, StatefulCapsElapsedTimeOnSolicitRetry) {
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_FALSE(scenario.transmissions.empty());
    EXPECT_EQ(scenario.transmissions.back().elapsed, 65535u);
}

TEST_F(LifeCycleTest, StatefulRetriesRequestAfterMissingReply) {
    scenario.advertisements = {true};
    scenario.response_available = {false, true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(transmitted_types(), (std::vector<uint8_t>{
        SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE
    }));
    EXPECT_EQ(scenario.transmissions.back().elapsed, lower_request[0] / 10);
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{lower_request[0]});
}

TEST_F(LifeCycleTest, StatefulStartsSolicitOverAfterRequestRetriesExhausted) {
    scenario.advertisements = {true};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    const auto types = transmitted_types();
    ASSERT_EQ(types.size(), SOLICIT_RETRANS_COUNT + REQUEST_RETRANS_COUNT + 3u);
    EXPECT_EQ(types.front(), SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(types[REQUEST_RETRANS_COUNT + 1], REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(types[REQUEST_RETRANS_COUNT + 2], SOLICIT_MESSAGE_TYPE);
}

TEST_F(LifeCycleTest, StatefulDelaysRestartAfterRequestRetriesExhausted) {
    scenario.advertisements = {true};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{MICROSECONDS_IN_SECONDS});
}

TEST_F(LifeCycleTest, StatefulRebindsWhenRenewalGetsNoReplyBeforeT2) {
    // T1 is 60 s, T2 is 90 s and the lease is valid for 120 s.
    scenario.clock = {1000, 1060, 1090, 1090, 1090, 1090, 1090};
    scenario.advertisements = {true};
    scenario.lease_exists = {true, true, false};
    scenario.response_available = {true, false, false, true};
    scenario.replies = {Reply::accepted, Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);

    ASSERT_EQ(scenario.transmissions.size(), 5u);
    EXPECT_EQ(scenario.transmissions[0].type, SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[1].type, REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[2].type, RENEW_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[3].type, RENEW_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[4].type, REBIND_MESSAGE_TYPE);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{REQUEST_MESSAGE_TYPE, REBIND_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, StatefulRestartsElapsedTimeOnRebind) {
    // T1 is 60 s, T2 is 90 s and the lease is valid for 120 s.
    scenario.clock = {1000, 1060, 1090, 1090, 1090, 1090, 1090};
    scenario.advertisements = {true};
    scenario.lease_exists = {true, true, false};
    scenario.response_available = {true, false, false, true};
    scenario.replies = {Reply::accepted, Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);

    ASSERT_EQ(scenario.transmissions.size(), 5u);
    EXPECT_EQ(scenario.transmissions[2].elapsed, 0u);
    EXPECT_EQ(scenario.transmissions[3].elapsed, renew_lower[0] / 10);
    EXPECT_EQ(scenario.transmissions[4].elapsed, 0u);
}

TEST_F(LifeCycleTest, StatefulDeclinesDuplicateAddressAfterRequest) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{
        SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE
    }));
}

TEST_F(LifeCycleTest, StatefulCleansUpDuplicateLeaseBeforeDeclining) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.advertisements = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycle(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::send, Event::send, Event::remove_addresses, Event::delete_lease, Event::send
    }));
}

TEST_F(LifeCycleTest, RapidCommitAcceptsDirectReplyWithoutRequest) {
    scenario.rapid_responses = {REPLY_MESSAGE_TYPE};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), 1u);
    EXPECT_EQ(scenario.transmissions[0].type, SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE});
}

TEST_F(LifeCycleTest, RapidCommitStopsWhenDirectReplyCannotBeParsed) {
    scenario.rapid_responses = {REPLY_MESSAGE_TYPE};
    scenario.replies = {Reply::unavailable};
    scenario.reply_has_sol_max_rt = true;
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE});
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE});
    EXPECT_TRUE(scenario.retry_delays.empty());
}

TEST_F(LifeCycleTest, RapidCommitFallsBackToRequestAfterAdvertisement) {
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    ASSERT_EQ(scenario.transmissions.size(), 2u);
    EXPECT_EQ(scenario.transmissions[0].type, SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(scenario.transmissions[1].type, REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{REQUEST_MESSAGE_TYPE});
}

TEST_F(LifeCycleTest, RapidCommitRestartsAfterFallbackRequestRetriesExhausted) {
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    const auto types = transmitted_types();
    ASSERT_EQ(types.size(), SOLICIT_RETRANS_COUNT + REQUEST_RETRANS_COUNT + 3u);
    EXPECT_EQ(types.front(), SOLICIT_MESSAGE_TYPE);
    EXPECT_EQ(types[REQUEST_RETRANS_COUNT + 1], REQUEST_MESSAGE_TYPE);
    EXPECT_EQ(types[REQUEST_RETRANS_COUNT + 2], SOLICIT_MESSAGE_TYPE);
}

TEST_F(LifeCycleTest, RapidCommitDelaysRestartAfterFallbackRequestRetriesExhausted) {
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{MICROSECONDS_IN_SECONDS});
}

TEST_F(LifeCycleTest, RapidCommitDeclinesDuplicateAddressAfterDirectReply) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.rapid_responses = {REPLY_MESSAGE_TYPE};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{SOLICIT_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, RapidCommitCleansUpDirectLeaseBeforeDeclining) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.rapid_responses = {REPLY_MESSAGE_TYPE};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::send, Event::remove_addresses, Event::delete_lease, Event::send
    }));
}

TEST_F(LifeCycleTest, RapidCommitDeclinesDuplicateAddressAfterFallbackRequest) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{
        SOLICIT_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE
    }));
}

TEST_F(LifeCycleTest, RapidCommitCleansUpFallbackLeaseBeforeDeclining) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.rapid_responses = {ADVERTISE_MESSAGE_TYPE};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    statefulLifeCycleRapidCommit(&scenario.config, interface, client_socket, mode);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::send, Event::send, Event::remove_addresses, Event::delete_lease, Event::send
    }));
}

TEST_F(LifeCycleTest, ConfirmReturnsWithoutOpeningSocketIfLeaseIsMissing) {
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    EXPECT_TRUE(scenario.events.empty());
}

TEST_F(LifeCycleTest, ReleaseReturnsWithoutOpeningSocketIfLeaseIsMissing) {
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    EXPECT_TRUE(scenario.events.empty());
}

TEST_F(LifeCycleTest, ConfirmRestoresLeaseEvenWhenSocketCreationFails) {
    scenario.lease_exists = {true};
    scenario.socket_fails = true;
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::copy_lease, Event::delete_lease, Event::open_socket, Event::restore_lease
    }));
}

TEST_F(LifeCycleTest, ConfirmRetriesBusyPort) {
    scenario.lease_exists = {true, false};
    scenario.bind_errors = {EADDRINUSE, 0};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 0);
    EXPECT_EQ(scenario.sleep_delays, std::vector<useconds_t>{100000});
    EXPECT_EQ(std::count(scenario.events.begin(), scenario.events.end(), Event::bind_socket), 2);
}

TEST_F(LifeCycleTest, ConfirmClosesSocketAfterLeaseRemoval) {
    scenario.lease_exists = {true, false};
    scenario.bind_errors = {EADDRINUSE, 0};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 0);
    EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{CONFIRM_MESSAGE_TYPE});
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::copy_lease, Event::delete_lease, Event::open_socket, Event::bind_socket,
        Event::bind_socket, Event::restore_lease, Event::send, Event::close_socket
    }));
}

TEST_F(LifeCycleTest, ConfirmClosesSocketIfReplyCannotBeParsed) {
    scenario.lease_exists = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ConfirmWaitsForValidReplyAfterRejectedReply) {
    scenario.lease_exists = {true};
    scenario.response_available = {true, true};
    scenario.replies = {Reply::rejected, Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 0);
    EXPECT_EQ(transmitted_types(), std::vector<uint8_t>{CONFIRM_MESSAGE_TYPE});
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{CONFIRM_MESSAGE_TYPE, CONFIRM_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, ConfirmClosesSocketAfterAcceptingSubsequentReply) {
    scenario.lease_exists = {true};
    scenario.response_available = {true, true};
    scenario.replies = {Reply::rejected, Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 0);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ConfirmRetriesDeclineAfterDuplicateAddress) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.lease_exists = {true};
    scenario.response_available = {true, false, true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    EXPECT_EQ(transmitted_types(), (std::vector<uint8_t>{
        CONFIRM_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE
    }));
    EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{decline_lower[0]});
}

TEST_F(LifeCycleTest, ConfirmClosesSocketAfterDecline) {
    scenario.dad_fails = true;
    scenario.expected_removed_type = DECLINE_MESSAGE_TYPE;
    scenario.lease_exists = {true};
    scenario.response_available = {true, false, true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ConfirmClosesSocketAfterRetransmissionLimit) {
    scenario.lease_exists = {true};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ConfirmStopsAtRetransmissionLimit) {
    scenario.lease_exists = {true};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    ASSERT_EQ(scenario.transmissions.size(), CONFIRM_RETRANS_COUNT + 1u);
    EXPECT_EQ(scenario.retry_delays.size(), CONFIRM_RETRANS_COUNT);
}

TEST_F(LifeCycleTest, ConfirmAccumulatesElapsedTimeAcrossRetransmissions) {
    scenario.lease_exists = {true};
    EXPECT_EQ(confirmLifeCycle(&scenario.config, interface), 1);
    ASSERT_EQ(scenario.transmissions.size(), CONFIRM_RETRANS_COUNT + 1u);
    uint32_t elapsed = 0;
    EXPECT_EQ(scenario.transmissions.front().elapsed, 0u);
    for (size_t i = 0; i < CONFIRM_RETRANS_COUNT; ++i) {
        elapsed += confirm_lower[i];
        EXPECT_EQ(scenario.transmissions[i + 1].elapsed, elapsed / 10);
    }
}

TEST_F(LifeCycleTest, ReleaseContinuesAfterRejectedReply) {
    scenario.lease_exists = {true};
    scenario.response_available = {true, true};
    scenario.replies = {Reply::rejected, Reply::accepted};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 0);
    EXPECT_EQ(scenario.reply_requests, (std::vector<uint8_t>{RELEASE_MESSAGE_TYPE, RELEASE_MESSAGE_TYPE}));
}

TEST_F(LifeCycleTest, ReleaseCleansUpLeaseAfterAcceptedReply) {
    scenario.lease_exists = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::accepted};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 0);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::copy_lease, Event::delete_lease, Event::open_socket, Event::bind_socket,
        Event::restore_lease, Event::send, Event::remove_addresses, Event::delete_lease, Event::close_socket
    }));
}

TEST_F(LifeCycleTest, ReleaseRestoresLeaseAfterClosingPermanentlyUnbindableSocket) {
    scenario.lease_exists = {true};
    scenario.bind_errors = {EACCES};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    EXPECT_EQ(scenario.events, (std::vector<Event>{
        Event::copy_lease, Event::delete_lease, Event::open_socket, Event::bind_socket,
        Event::close_socket, Event::restore_lease
    }));
}

TEST_F(LifeCycleTest, ReleaseSkipsRetryAfterPermanentBindFailure) {
    scenario.lease_exists = {true};
    scenario.bind_errors = {EACCES};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    EXPECT_TRUE(scenario.sleep_delays.empty());
}

TEST_F(LifeCycleTest, ReleaseClosesSocketAfterRetransmissionLimit) {
    scenario.lease_exists = {true};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ReleaseStopsAtRetransmissionLimit) {
    scenario.lease_exists = {true};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    ASSERT_EQ(scenario.transmissions.size(), RELEASE_RETRANS_COUNT + 1u);
    EXPECT_EQ(scenario.retry_delays.size(), RELEASE_RETRANS_COUNT);
}

TEST_F(LifeCycleTest, ReleaseAccumulatesElapsedTimeAcrossRetransmissions) {
    scenario.lease_exists = {true};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    ASSERT_EQ(scenario.transmissions.size(), RELEASE_RETRANS_COUNT + 1u);
    uint32_t elapsed = 0;
    EXPECT_EQ(scenario.transmissions.front().elapsed, 0u);
    for (size_t i = 0; i < RELEASE_RETRANS_COUNT; ++i) {
        elapsed += release_lower[i];
        EXPECT_EQ(scenario.transmissions[i + 1].elapsed, elapsed / 10);
    }
}

TEST_F(LifeCycleTest, ReleaseClosesSocketIfReplyCannotBeParsed) {
    scenario.lease_exists = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    ASSERT_FALSE(scenario.events.empty());
    EXPECT_EQ(scenario.events.back(), Event::close_socket);
}

TEST_F(LifeCycleTest, ReleaseKeepsRestoredLeaseIfReplyCannotBeParsed) {
    scenario.lease_exists = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    auto restored = std::find(scenario.events.begin(), scenario.events.end(), Event::restore_lease);
    ASSERT_NE(restored, scenario.events.end());
    EXPECT_EQ(std::find(restored, scenario.events.end(), Event::delete_lease), scenario.events.end());
}

TEST_F(LifeCycleTest, ReleaseKeepsInterfaceAddressesIfReplyCannotBeParsed) {
    scenario.lease_exists = {true};
    scenario.response_available = {true};
    scenario.replies = {Reply::unavailable};
    EXPECT_EQ(releaseLifeCycle(&scenario.config, interface), 1);
    EXPECT_EQ(std::count(scenario.events.begin(), scenario.events.end(), Event::remove_addresses), 0);
}

TEST_F(LifeCycleDeathTest, StatelessSchedulesRefreshAfterValidReply) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.refresh_sleeps, std::vector<unsigned int>{2u});
    });
}

TEST_F(LifeCycleDeathTest, StatelessAcceptsFirstValidReplyWithoutRetransmission) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.reply_requests, std::vector<uint8_t>{INFORMATION_REQUEST_MESSAGE_TYPE});
        EXPECT_EQ(scenario.transmissions.size(), 1u);
    });
}

TEST_F(LifeCycleDeathTest, StatelessWaitsOneDayWithoutRefreshOption) {
    scenario.response_available = {true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.refresh_sleeps, std::vector<unsigned int>{86400u});
    });
}

TEST_F(LifeCycleDeathTest, StatelessRetransmitsBeforeSchedulingRefresh) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {false, false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.retry_delays, std::vector<uint64_t>{lower_solicit[0]});
        EXPECT_EQ(scenario.transmissions.size(), 2u);
    });
}

TEST_F(LifeCycleDeathTest, StatelessRetryAdvancesElapsedTime) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {false, false, true};
    expect_on_stateless_restart([] {
        ASSERT_EQ(scenario.transmissions.size(), 2u);
        EXPECT_EQ(scenario.transmissions.back().elapsed, lower_solicit[0] / 10);
    });
}

TEST_F(LifeCycleDeathTest, StatelessUsesAdvertisedRefreshAfterRetry) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {false, false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.refresh_sleeps, std::vector<unsigned int>{2u});
    });
}

TEST_F(LifeCycleDeathTest, StatelessRetriesAfterInvalidRetransmittedReply) {
    scenario.refresh_seconds = 2;
    scenario.response_available = {false, true, true};
    scenario.stateless_reply_valid = {false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.reply_requests.size(), 3u);
        EXPECT_EQ(scenario.transmissions.size(), 2u);
    });
}

TEST_F(LifeCycleDeathTest, StatelessUsesDefaultWhenRetransmittedReplyOmitsRefreshOption) {
    scenario.response_available = {false, false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.refresh_sleeps, std::vector<unsigned int>{86400u});
    });
}

TEST_F(LifeCycleDeathTest, StatelessCapsRetryDelayAtAdvertisedMaximum) {
    scenario.refresh_seconds = 2;
    scenario.info_max_rt_seconds = 1;
    scenario.response_available = {true, false, false, true};
    scenario.stateless_reply_valid = {false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.retry_delays, (std::vector<uint64_t>{1000u, 1000u}));
    });
}

TEST_F(LifeCycleDeathTest, StatelessAccumulatesElapsedTimeOnCappedRetries) {
    scenario.refresh_seconds = 2;
    scenario.info_max_rt_seconds = 1;
    scenario.response_available = {true, false, false, true};
    scenario.stateless_reply_valid = {false, true};
    expect_on_stateless_restart([] {
        ASSERT_EQ(scenario.transmissions.size(), 3u);
        EXPECT_EQ(scenario.transmissions[1].elapsed, 100u);
        EXPECT_EQ(scenario.transmissions[2].elapsed, 200u);
    });
}

TEST_F(LifeCycleDeathTest, StatelessProcessesReplyAfterCappedRetries) {
    scenario.refresh_seconds = 2;
    scenario.info_max_rt_seconds = 1;
    scenario.response_available = {true, false, false, true};
    scenario.stateless_reply_valid = {false, true};
    expect_on_stateless_restart([] {
        EXPECT_EQ(scenario.reply_requests.size(), 4u);
        EXPECT_EQ(scenario.refresh_sleeps, std::vector<unsigned int>{2u});
    });
}

TEST_F(LifeCycleDeathTest, StatelessRestartsAfterExhaustingRequestRetries) {
    expect_on_stateless_restart([] {
        EXPECT_TRUE(scenario.refresh_sleeps.empty());
        EXPECT_EQ(scenario.transmissions.size(), INFO_REQUEST_RETRANS_COUNT + 1u);
        EXPECT_EQ(scenario.retry_delays.size(), INFO_REQUEST_RETRANS_COUNT);
        EXPECT_EQ(scenario.reply_requests.size(), INFO_REQUEST_RETRANS_COUNT + 1u);
    });
}

TEST_F(LifeCycleDeathTest, StatelessSaturatesElapsedTimeOnUnansweredRequests) {
    expect_on_stateless_restart([] {
        ASSERT_FALSE(scenario.transmissions.empty());
        ASSERT_EQ(scenario.transmissions.back().type, INFORMATION_REQUEST_MESSAGE_TYPE);
        EXPECT_EQ(scenario.transmissions.back().elapsed, 65535u);
    });
}
}
