#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

extern "C" {
#include "dhcomplyBuildMessageFunctions.h"
}

namespace {
constexpr std::array<uint8_t, MAC_ADDRESS_LENGTH> client_mac{0x02, 0x13, 0x24, 0x35, 0x46, 0x57};
constexpr uint32_t random_value = 0xaf123456;
constexpr uint32_t transaction_id = 0x123456;
constexpr uint128_t prefix = static_cast<uint128_t>(0x20010db8) << 96;
constexpr uint128_t address = prefix | 0xabcd;
constexpr char address_lease_document[] = R"({"server_duid":{"duid":"00:03:00:01:aB:CD:eF"},"leases":[{
    "type":"IANA","iaid":"abc","t1":300,"t2":600,
    "preferred_lifetime":900,"valid_lifetime":1200,"address":"2001:db8::abcd"}]})";
const char *lease_document = nullptr;
}

extern "C" int __wrap_get_mac_address(const char *, uint8_t *mac)
{
    std::memcpy(mac, client_mac.data(), client_mac.size());
    return 0;
}

extern "C" uint32_t __wrap_unpredictable_random()
{
    return random_value;
}

extern "C" cJSON *__wrap_readLease(const char *)
{
    return lease_document ? cJSON_Parse(lease_document) : nullptr;
}

namespace {
struct MessageDeleter {
    bool owns_identifiers = false;

    void operator()(dhcpv6_message_t *message) const
    {
        for (size_t i = 0; i < message->option_count; ++i) {
            auto &option = message->option_list[i];
            if (option.option_code == ORO_OPTION_CODE) {
                std::free(option.option_request_t.option_request);
            } else if (owns_identifiers && option.option_code == CLIENT_ID_OPTION_CODE) {
                std::free(option.client_id_t.duid.mac);
            } else if (owns_identifiers && option.option_code == SERVER_ID_OPTION_CODE) {
                std::free(option.server_id_t.duid.mac);
            }
        }
        std::free(message->option_list);
        std::free(message);
    }
};

using Message = std::unique_ptr<dhcpv6_message_t, MessageDeleter>;

class MessageBuilderTest : public testing::Test {
protected:
    static constexpr const char *interface_name = "test0";

    void TearDown() override { lease_document = nullptr; }

    void expect_header(const Message &message, uint8_t type, unsigned count)
    {
        EXPECT_EQ(message->message_type, type);
        EXPECT_EQ(message->transaction_id, transaction_id);
        EXPECT_EQ(message->option_count, count);
    }

    void expect_client_identifier(const dhcpv6_option_t &option)
    {
        EXPECT_EQ(option.option_code, CLIENT_ID_OPTION_CODE);
        EXPECT_EQ(option.option_length, 10);
        EXPECT_EQ(option.client_id_t.duid.duid_type, 3);
        EXPECT_EQ(option.client_id_t.duid.hw_type, 1);
        ASSERT_NE(option.client_id_t.duid.mac, nullptr);
        EXPECT_EQ(std::memcmp(option.client_id_t.duid.mac, client_mac.data(), client_mac.size()), 0);
    }

    void expect_elapsed_time(const dhcpv6_option_t &option)
    {
        EXPECT_EQ(option.option_code, ELAPSED_TIME_OPTION_CODE);
        EXPECT_EQ(option.option_length, 2);
        EXPECT_EQ(option.elapsed_time_t.elapsed_time_value, 0);
    }
};

std::array<dhcpv6_option_t, 2> address_association(uint32_t iaid, uint128_t value)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_NA_OPTION_CODE;
    options[0].option_length = 40;
    options[0].ia_na_t.iaid = iaid;
    options[0].ia_na_t.t1 = 300;
    options[0].ia_na_t.t2 = 600;
    options[1].option_code = IA_ADDR_OPTION_CODE;
    options[1].option_length = 24;
    options[1].ia_address_t.ipv6_address = value;
    options[1].ia_address_t.preferred_lifetime = 900;
    options[1].ia_address_t.valid_lifetime = 1200;
    return options;
}

template <size_t N>
dhcpv6_message_t example(uint8_t type, std::array<dhcpv6_option_t, N> &options)
{
    dhcpv6_message_t message{};
    message.message_type = type;
    message.option_count = N;
    message.option_list = options.data();
    return message;
}

std::array<dhcpv6_option_t, 2> prefix_association()
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_PD_OPTION_CODE;
    options[0].option_length = 41;
    options[0].ia_pd_t.iaid = 0xdef;
    options[0].ia_pd_t.t1 = 300;
    options[0].ia_pd_t.t2 = 600;
    options[1].option_code = IAPREFIX_OPTION_CODE;
    options[1].option_length = 25;
    options[1].ia_prefix_t.ipv6_prefix = prefix;
    options[1].ia_prefix_t.prefix_length = 56;
    options[1].ia_prefix_t.preferred_lifetime = 900;
    options[1].ia_prefix_t.valid_lifetime = 1200;
    return options;
}

dhcpv6_message_t *renew_address_request(dhcpv6_message_t *reply, config_t *config)
{
    dhcpv6_message_t request{};
    request.message_type = REQUEST_MESSAGE_TYPE;
    return buildRenew(reply, &request, config);
}

struct ExchangeBuilder {
    const char *name;
    uint8_t response_type;
    uint8_t type;
    dhcpv6_message_t *(*build)(dhcpv6_message_t *, config_t *);
};

constexpr ExchangeBuilder request_builder{
    "Request", ADVERTISE_MESSAGE_TYPE, REQUEST_MESSAGE_TYPE, buildRequest};
constexpr ExchangeBuilder renew_builder{
    "Renew", REPLY_MESSAGE_TYPE, RENEW_MESSAGE_TYPE, renew_address_request};
constexpr ExchangeBuilder rebind_builder{
    "Rebind", REPLY_MESSAGE_TYPE, REBIND_MESSAGE_TYPE, buildRebind};
constexpr ExchangeBuilder decline_builder{
    "Decline", REPLY_MESSAGE_TYPE, DECLINE_MESSAGE_TYPE, buildDecline};

std::string exchange_name(const testing::TestParamInfo<ExchangeBuilder> &info)
{
    return info.param.name;
}

TEST_F(MessageBuilderTest, SolicitCreatesHeader)
{
    config_t config{};
    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    expect_header(message, SOLICIT_MESSAGE_TYPE, 2);
}

TEST_F(MessageBuilderTest, SolicitCreatesClientIdentifier)
{
    config_t config{};
    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_client_identifier(message->option_list[0]);
}

TEST_F(MessageBuilderTest, SolicitInitializesElapsedTime)
{
    config_t config{};
    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_elapsed_time(message->option_list[1]);
}

TEST_F(MessageBuilderTest, SolicitIncludesRequestedOptions)
{
    uint8_t requested_options[] = {DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE};
    config_t config{};
    config.oro_list = requested_options;
    config.oro_list_length = 2;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, ORO_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 4);
    ASSERT_NE(options[2].option_request_t.option_request, nullptr);
    EXPECT_EQ(std::memcmp(options[2].option_request_t.option_request, requested_options, 2), 0);
}

TEST_F(MessageBuilderTest, SolicitEnablesRapidCommit)
{
    config_t config{};
    config.rapid_commit = true;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, RAPID_COMMIT_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 0);
}

TEST_F(MessageBuilderTest, SolicitAcceptsReconfiguration)
{
    config_t config{};
    config.reconfigure = true;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, RECONF_ACCEPT_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 0);
}

TEST_F(MessageBuilderTest, SolicitIncludesAddressAssociation)
{
    char address_iaid[] = "abc";
    config_t config{};
    config.na = true;
    config.ianaIaid = address_iaid;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 12);
    EXPECT_EQ(options[2].ia_na_t.iaid, 0xabc);
}

TEST_F(MessageBuilderTest, SolicitIncludesPrefixAssociation)
{
    char prefix_iaid[] = "def";
    config_t config{};
    config.pd = true;
    config.iapdIaid = prefix_iaid;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, IA_PD_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 12);
    EXPECT_EQ(options[2].ia_pd_t.iaid, 0xdef);
}

TEST_F(MessageBuilderTest, SolicitIncludesAddressHint)
{
    char address_iaid[] = "abc";
    uint128_t address_hint = address;
    config_t config{};
    config.na = true;
    config.ianaIaid = address_iaid;
    config.ia_hint.preferred_address = &address_hint;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 40);
    EXPECT_EQ(options[3].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(options[3].ia_address_t.ipv6_address == address);
    EXPECT_EQ(options[3].ia_address_t.valid_lifetime, 0);
}

TEST_F(MessageBuilderTest, SolicitIncludesPrefixHint)
{
    char prefix_iaid[] = "def";
    uint128_t prefix_hint = prefix;
    uint8_t prefix_length = 56;
    config_t config{};
    config.pd = true;
    config.iapdIaid = prefix_iaid;
    config.ia_hint.preferred_prefix = &prefix_hint;
    config.ia_hint.preferred_prefix_length = &prefix_length;

    Message message(buildSolicit(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    const auto *options = message->option_list;
    EXPECT_EQ(options[2].option_code, IA_PD_OPTION_CODE);
    EXPECT_EQ(options[2].option_length, 41);
    EXPECT_EQ(options[3].option_code, IAPREFIX_OPTION_CODE);
    EXPECT_TRUE(options[3].ia_prefix_t.ipv6_prefix == prefix);
    EXPECT_EQ(options[3].ia_prefix_t.prefix_length, 56);
}

class AddressExchangeBuilderTest : public MessageBuilderTest {
protected:
    std::array<dhcpv6_option_t, 2> options = address_association(0xabc, address);
    dhcpv6_message_t advertisement = example(ADVERTISE_MESSAGE_TYPE, options);
    dhcpv6_message_t reply = example(REPLY_MESSAGE_TYPE, options);
    config_t config{};
};

TEST_F(AddressExchangeBuilderTest, RequestCreatesHeader)
{
    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    expect_header(message, REQUEST_MESSAGE_TYPE, 3);
}

TEST_F(AddressExchangeBuilderTest, RequestCopiesAdvertisedAddress)
{
    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].ia_na_t.iaid, 0xabc);
    EXPECT_EQ(message->option_list[1].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[1].ia_address_t.ipv6_address == address);
}

TEST_F(AddressExchangeBuilderTest, RequestResetsAdvertisedAddressTimers)
{
    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].ia_na_t.t1, 0);
    EXPECT_EQ(message->option_list[0].ia_na_t.t2, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.preferred_lifetime, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.valid_lifetime, 0);
}

TEST_F(AddressExchangeBuilderTest, RequestInitializesElapsedTime)
{
    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    expect_elapsed_time(message->option_list[2]);
}

TEST_F(AddressExchangeBuilderTest, RequestPreservesTimersInOriginalAdvertisement)
{
    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    EXPECT_EQ(options[0].ia_na_t.t1, 300);
    EXPECT_EQ(options[1].ia_address_t.valid_lifetime, 1200);
}

TEST_F(MessageBuilderTest, RequestRetainsAdvertisedSolMaxRt)
{
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = SOL_MAX_RT_OPTION_CODE;
    options[0].option_length = 4;
    options[0].SOL_MAX_RT_t.SOL_MAX_RT_value = 3600;
    auto advertisement = example(ADVERTISE_MESSAGE_TYPE, options);
    config_t config{};

    Message message(buildRequest(&advertisement, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    EXPECT_EQ(message->option_list[0].option_code, SOL_MAX_RT_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].SOL_MAX_RT_t.SOL_MAX_RT_value, 3600);
}

class OfferOptionBuilderTest : public MessageBuilderTest,
                               public testing::WithParamInterface<ExchangeBuilder> {};

TEST_P(OfferOptionBuilderTest, RetainsZeroLengthResponseOption)
{
    const auto &builder = GetParam();
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = RAPID_COMMIT_OPTION_CODE;
    auto reply = example(builder.response_type, options);
    config_t config{};

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    EXPECT_EQ(message->option_list[0].option_code, RAPID_COMMIT_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].option_length, 0);
}

INSTANTIATE_TEST_SUITE_P(
    MessageTypes, OfferOptionBuilderTest,
    testing::Values(request_builder, rebind_builder), exchange_name);

TEST_F(AddressExchangeBuilderTest, RenewCreatesHeader)
{
    Message message(renew_address_request(&reply, &config));

    ASSERT_NE(message, nullptr);
    expect_header(message, RENEW_MESSAGE_TYPE, 3);
}

TEST_F(AddressExchangeBuilderTest, RenewCopiesAddressAssociation)
{
    Message message(renew_address_request(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].ia_na_t.iaid, 0xabc);
    EXPECT_EQ(message->option_list[1].option_code, IA_ADDR_OPTION_CODE);
}

TEST_F(AddressExchangeBuilderTest, RenewResetsAddressTimersFromReply)
{
    Message message(renew_address_request(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].ia_na_t.t1, 0);
    EXPECT_EQ(message->option_list[0].ia_na_t.t2, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.valid_lifetime, 0);
}

TEST_F(AddressExchangeBuilderTest, RenewInitializesElapsedTime)
{
    Message message(renew_address_request(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    expect_elapsed_time(message->option_list[2]);
}

TEST_F(MessageBuilderTest, RenewIgnoresResponseStatusOption)
{
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = STATUS_CODE_OPTION_CODE;
    options[0].option_length = 2;
    auto reply = example(REPLY_MESSAGE_TYPE, options);
    config_t config{};

    Message message(renew_address_request(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 1);
    expect_elapsed_time(message->option_list[0]);
}

TEST_F(MessageBuilderTest, RenewAfterConfirmUsesConfirmedAddress)
{
    auto requested_options = address_association(0xabc, address);
    auto reply_options = address_association(0x765, address - 1);
    auto confirm = example(CONFIRM_MESSAGE_TYPE, requested_options);
    auto reply = example(REPLY_MESSAGE_TYPE, reply_options);
    config_t config{};

    Message message(buildRenew(&reply, &confirm, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[1].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[1].ia_na_t.iaid, 0xabc);
    EXPECT_EQ(message->option_list[2].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[2].ia_address_t.ipv6_address == address);
}

TEST_F(MessageBuilderTest, RenewAfterConfirmInitializesElapsedTime)
{
    auto requested_options = address_association(0xabc, address);
    auto reply_options = address_association(0x765, address - 1);
    auto confirm = example(CONFIRM_MESSAGE_TYPE, requested_options);
    auto reply = example(REPLY_MESSAGE_TYPE, reply_options);
    config_t config{};

    Message message(buildRenew(&reply, &confirm, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    expect_elapsed_time(message->option_list[0]);
}

TEST_F(MessageBuilderTest, RenewAfterConfirmOmitsAssociationWithoutAddress)
{
    std::array<dhcpv6_option_t, 3> confirm_options{};
    confirm_options[0].option_code = ELAPSED_TIME_OPTION_CODE;
    confirm_options[1].option_code = IA_NA_OPTION_CODE;
    confirm_options[2].option_code = RECONF_ACCEPT_OPTION_CODE;
    auto confirm = example(CONFIRM_MESSAGE_TYPE, confirm_options);
    std::array<dhcpv6_option_t, 0> reply_options{};
    auto reply = example(REPLY_MESSAGE_TYPE, reply_options);
    config_t config{};

    Message message(buildRenew(&reply, &confirm, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 1);
    expect_elapsed_time(message->option_list[0]);
}

TEST_F(AddressExchangeBuilderTest, RebindCopiesAddressAssociation)
{
    Message message(buildRebind(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].ia_na_t.iaid, 0xabc);
    EXPECT_EQ(message->option_list[1].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[1].ia_address_t.ipv6_address == address);
}

TEST_F(AddressExchangeBuilderTest, RebindResetsAddressTimers)
{
    Message message(buildRebind(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].ia_na_t.t1, 0);
    EXPECT_EQ(message->option_list[0].ia_na_t.t2, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.preferred_lifetime, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.valid_lifetime, 0);
}

class ExchangeOptionsTest : public MessageBuilderTest,
                            public testing::WithParamInterface<ExchangeBuilder> {
protected:
    Message build_with_prefix() {
        const auto &builder = GetParam();
        auto options = prefix_association();
        auto reply = example(builder.response_type, options);
        config_t config{};
        return Message(builder.build(&reply, &config));
    }
};

TEST_P(ExchangeOptionsTest, BuildsHeaderForPrefixAssociation)
{
    Message message = build_with_prefix();

    ASSERT_NE(message, nullptr);
    expect_header(message, GetParam().type, 3);
}

TEST_P(ExchangeOptionsTest, CopiesDelegatedPrefix)
{
    Message message = build_with_prefix();

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].option_code, IA_PD_OPTION_CODE);
    EXPECT_EQ(message->option_list[0].ia_pd_t.iaid, 0xdef);
    EXPECT_EQ(message->option_list[1].option_code, IAPREFIX_OPTION_CODE);
    EXPECT_TRUE(message->option_list[1].ia_prefix_t.ipv6_prefix == prefix);
    EXPECT_EQ(message->option_list[1].ia_prefix_t.prefix_length, 56);
}

TEST_P(ExchangeOptionsTest, ResetsDelegatedPrefixTimers)
{
    Message message = build_with_prefix();

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].ia_pd_t.t1, 0);
    EXPECT_EQ(message->option_list[0].ia_pd_t.t2, 0);
    EXPECT_EQ(message->option_list[1].ia_prefix_t.preferred_lifetime, 0);
    EXPECT_EQ(message->option_list[1].ia_prefix_t.valid_lifetime, 0);
}

TEST_P(ExchangeOptionsTest, InitializesElapsedTimeForPrefixAssociation)
{
    Message message = build_with_prefix();

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    expect_elapsed_time(message->option_list[2]);
}

TEST_P(ExchangeOptionsTest, AddsRequestedOptionsFromConfiguration)
{
    const auto &builder = GetParam();
    std::array<dhcpv6_option_t, 0> options{};
    auto reply = example(builder.response_type, options);
    uint8_t requested[] = {DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE};
    config_t config{};
    config.oro_list = requested;
    config.oro_list_length = sizeof(requested);

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    const auto &option = message->option_list[1];
    EXPECT_EQ(option.option_code, ORO_OPTION_CODE);
    EXPECT_EQ(option.option_length, 4);
    ASSERT_NE(option.option_request_t.option_request, nullptr);
    EXPECT_NE(option.option_request_t.option_request, requested);
    EXPECT_EQ(std::memcmp(option.option_request_t.option_request, requested, sizeof(requested)), 0);
}

TEST_P(ExchangeOptionsTest, RetainsDnsServer)
{
    const auto &builder = GetParam();
    uint8_t server[16] = {0x20, 1, 0x0d, 0xb8};
    server[15] = 1;
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = DNS_SERVERS_OPTION_CODE;
    options[0].option_length = sizeof(server);
    options[0].dns_recursive_name_server_t.dns_servers = server;
    auto reply = example(builder.response_type, options);
    config_t config{};

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    const auto &option = message->option_list[0];
    EXPECT_EQ(option.option_code, DNS_SERVERS_OPTION_CODE);
    EXPECT_EQ(option.option_length, sizeof(server));
    ASSERT_NE(option.dns_recursive_name_server_t.dns_servers, nullptr);
    EXPECT_EQ(std::memcmp(option.dns_recursive_name_server_t.dns_servers, server, sizeof(server)), 0);
}

TEST_P(ExchangeOptionsTest, RetainsDomainSearchList)
{
    const auto &builder = GetParam();
    char domain[] = {1, 'a', 4, 't', 'e', 's', 't', 0};
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = DOMAIN_SEARCH_LIST_OPTION_CODE;
    options[0].option_length = sizeof(domain);
    options[0].domain_search_list_t.search_list = domain;
    auto reply = example(builder.response_type, options);
    config_t config{};

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    const auto &option = message->option_list[0];
    EXPECT_EQ(option.option_code, DOMAIN_SEARCH_LIST_OPTION_CODE);
    EXPECT_EQ(option.option_length, sizeof(domain));
    ASSERT_NE(option.domain_search_list_t.search_list, nullptr);
    EXPECT_EQ(std::memcmp(option.domain_search_list_t.search_list, domain, sizeof(domain)), 0);
}

INSTANTIATE_TEST_SUITE_P(
    MessageTypes, ExchangeOptionsTest,
    testing::Values(request_builder, renew_builder, rebind_builder), exchange_name);

class ClientIdentifierBuilderTest : public MessageBuilderTest,
                                    public testing::WithParamInterface<ExchangeBuilder> {};

TEST_P(ClientIdentifierBuilderTest, CopiesBorrowedClientIdentifier)
{
    const auto &builder = GetParam();
    auto mac = client_mac;
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = CLIENT_ID_OPTION_CODE;
    options[0].option_length = 10;
    options[0].client_id_t.duid = {3, 1, mac.data()};
    auto reply = example(builder.response_type, options);
    config_t config{};

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_client_identifier(message->option_list[0]);
}

INSTANTIATE_TEST_SUITE_P(
    MessageTypes, ClientIdentifierBuilderTest,
    testing::Values(request_builder, renew_builder, rebind_builder, decline_builder), exchange_name);

class ServerIdentifierBuilderTest : public MessageBuilderTest,
                                    public testing::WithParamInterface<ExchangeBuilder> {};

TEST_P(ServerIdentifierBuilderTest, RetainsServerIdentifier)
{
    const auto &builder = GetParam();
    uint8_t identifier[] = {0x12, 0x34, 0x56};
    std::array<dhcpv6_option_t, 1> options{};
    options[0].option_code = SERVER_ID_OPTION_CODE;
    options[0].option_length = 7;
    options[0].server_id_t.duid = {3, 1, identifier};
    auto reply = example(builder.response_type, options);
    config_t config{};

    Message message(builder.build(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    const auto &option = message->option_list[0];
    EXPECT_EQ(option.option_code, SERVER_ID_OPTION_CODE);
    EXPECT_EQ(option.option_length, 7);
    EXPECT_EQ(option.server_id_t.duid.duid_type, 3);
    EXPECT_EQ(option.server_id_t.duid.hw_type, 1);
    ASSERT_NE(option.server_id_t.duid.mac, nullptr);
    EXPECT_EQ(std::memcmp(option.server_id_t.duid.mac, identifier, sizeof(identifier)), 0);
}

INSTANTIATE_TEST_SUITE_P(
    MessageTypes, ServerIdentifierBuilderTest,
    testing::Values(request_builder, renew_builder, decline_builder), exchange_name);

class MixedLeaseDeclineTest : public MessageBuilderTest {
protected:
    void SetUp() override {
        const auto addresses = address_association(0xabc, address);
        options = {addresses[0], addresses[1], {}};
        options[2].option_code = IA_PD_OPTION_CODE;
        options[2].option_length = 12;
        reply = example(REPLY_MESSAGE_TYPE, options);
    }

    std::array<dhcpv6_option_t, 3> options{};
    dhcpv6_message_t reply{};
    config_t config{};
};

TEST_F(MixedLeaseDeclineTest, DeclineKeepsDeclinedAddress)
{
    Message message(buildDecline(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[1].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[1].ia_address_t.ipv6_address == address);
}

TEST_F(MixedLeaseDeclineTest, DeclineResetsAddressTimers)
{
    Message message(buildDecline(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[0].ia_na_t.t1, 0);
    EXPECT_EQ(message->option_list[1].ia_address_t.valid_lifetime, 0);
}

TEST_F(MixedLeaseDeclineTest, DeclineOmitsDelegatedPrefix) {
    Message message(buildDecline(&reply, &config));

    ASSERT_NE(message, nullptr);
    for (size_t i = 0; i < message->option_count; ++i) {
        EXPECT_NE(message->option_list[i].option_code, IA_PD_OPTION_CODE);
    }
}

TEST_F(MixedLeaseDeclineTest, DeclineCreatesHeader)
{
    Message message(buildDecline(&reply, &config));

    ASSERT_NE(message, nullptr);
    expect_header(message, DECLINE_MESSAGE_TYPE, 3);
}

TEST_F(MixedLeaseDeclineTest, DeclineInitializesElapsedTime)
{
    Message message(buildDecline(&reply, &config));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    expect_elapsed_time(message->option_list[2]);
}

TEST_F(MessageBuilderTest, InformationRequestIncludesRequestedOptions)
{
    uint8_t requested_options[] = {DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE};
    config_t config{};
    config.oro_list = requested_options;
    config.oro_list_length = 2;

    Message message(buildInformationRequest(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto &request = message->option_list[2];
    EXPECT_EQ(request.option_code, ORO_OPTION_CODE);
    EXPECT_EQ(request.option_length, 4);
    ASSERT_NE(request.option_request_t.option_request, nullptr);
    EXPECT_EQ(std::memcmp(request.option_request_t.option_request, requested_options, 2), 0);
}

TEST_F(MessageBuilderTest, InformationRequestCreatesHeader)
{
    uint8_t requested_options[] = {DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE};
    config_t config{};
    config.oro_list = requested_options;
    config.oro_list_length = 2;

    Message message(buildInformationRequest(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    expect_header(message, INFORMATION_REQUEST_MESSAGE_TYPE, 3);
}

TEST_F(MessageBuilderTest, InformationRequestOmitsUnconfiguredOptionRequest)
{
    config_t config{};

    Message message(buildInformationRequest(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    for (size_t i = 0; i < message->option_count; ++i) {
        EXPECT_NE(message->option_list[i].option_code, ORO_OPTION_CODE);
    }
}

TEST_F(MessageBuilderTest, InformationRequestCreatesClientIdentifier)
{
    config_t config{};

    Message message(buildInformationRequest(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_client_identifier(message->option_list[0]);
}

TEST_F(MessageBuilderTest, InformationRequestInitializesElapsedTime)
{
    config_t config{};

    Message message(buildInformationRequest(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_elapsed_time(message->option_list[1]);
}

TEST_F(MessageBuilderTest, ConfirmRejectsMissingLease)
{
    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;

    EXPECT_EQ(buildConfirm(&config, interface_name, &t1, &t2, &valid), nullptr);
}

class SavedAddressLeaseTest : public MessageBuilderTest {
protected:
    void SetUp() override { lease_document = address_lease_document; }

    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;
};

TEST_F(SavedAddressLeaseTest, ConfirmBuildsAddressLease)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[2].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[2].ia_na_t.iaid, 0xabc);
    EXPECT_EQ(message->option_list[3].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[3].ia_address_t.ipv6_address == address);
}

TEST_F(SavedAddressLeaseTest, ConfirmResetsAddressLifetimes)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[3].ia_address_t.preferred_lifetime, 0);
    EXPECT_EQ(message->option_list[3].ia_address_t.valid_lifetime, 0);
}

TEST_F(SavedAddressLeaseTest, ConfirmRestoresLeaseTimers)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    EXPECT_EQ(t1, 300);
    EXPECT_EQ(t2, 600);
    EXPECT_EQ(valid, 1200);
}

TEST_F(SavedAddressLeaseTest, ConfirmCreatesHeader)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    expect_header(message, CONFIRM_MESSAGE_TYPE, 4);
}

TEST_F(SavedAddressLeaseTest, ConfirmCreatesClientIdentifier)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    expect_client_identifier(message->option_list[0]);
}

TEST_F(SavedAddressLeaseTest, ConfirmInitializesElapsedTime)
{
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    expect_elapsed_time(message->option_list[1]);
}

TEST_F(MessageBuilderTest, ConfirmKeepsMaximumTimersAcrossAddressLeases)
{
    lease_document = R"({
        "server_duid":{"duid":"00:03:00:01:12:34:56"},
        "leases":[
            {"type":"IANA","iaid":"abc","t1":300,"t2":600,"preferred_lifetime":900,
             "valid_lifetime":1200,"address":"2001:db8::abcd"},
            {"type":"IANA","iaid":"def","t1":200,"t2":400,"preferred_lifetime":600,
             "valid_lifetime":800,"address":"2001:db8::abce"}
        ]})";
    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;

    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    EXPECT_EQ(message->option_count, 6);
    EXPECT_EQ(t1, 300);
    EXPECT_EQ(t2, 600);
    EXPECT_EQ(valid, 1200);
}

TEST_F(MessageBuilderTest, ConfirmAddsRequestedOptions)
{
    lease_document = R"({"leases":[]})";
    uint8_t requested[] = {DNS_SERVERS_OPTION_CODE};
    config_t config{};
    config.oro_list = requested;
    config.oro_list_length = sizeof(requested);
    uint32_t t1 = 0, t2 = 0, valid = 0;

    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    const auto &option = message->option_list[2];
    EXPECT_EQ(option.option_code, ORO_OPTION_CODE);
    EXPECT_EQ(option.option_length, 2);
    ASSERT_NE(option.option_request_t.option_request, nullptr);
    EXPECT_EQ(option.option_request_t.option_request[0], DNS_SERVERS_OPTION_CODE);
}

TEST_F(MessageBuilderTest, ConfirmAcceptsReconfigurationWhenEnabled)
{
    lease_document = R"({"leases":[]})";
    config_t config{};
    config.reconfigure = true;
    uint32_t t1 = 0, t2 = 0, valid = 0;

    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].option_code, RECONF_ACCEPT_OPTION_CODE);
    EXPECT_EQ(message->option_list[2].option_length, 0);
}

TEST_F(MessageBuilderTest, ConfirmWithDelegatedPrefixBuildsRebind)
{
    lease_document = R"({"leases":[{
        "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
        "valid_lifetime":1200,"prefix":"2001:db8::/56","prefix_length":56}]})";
    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;

    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    expect_header(message, REBIND_MESSAGE_TYPE, 4);
    EXPECT_EQ(message->option_list[2].option_code, IA_PD_OPTION_CODE);
    EXPECT_EQ(message->option_list[2].ia_pd_t.iaid, 0xdef);
    EXPECT_EQ(message->option_list[3].option_code, IAPREFIX_OPTION_CODE);
    EXPECT_TRUE(message->option_list[3].ia_prefix_t.ipv6_prefix == prefix);
    EXPECT_EQ(message->option_list[3].ia_prefix_t.prefix_length, 56);
}

TEST_F(MessageBuilderTest, ReleaseRejectsMissingLease)
{
    config_t config{};

    EXPECT_EQ(buildRelease(&config, interface_name), nullptr);
}

TEST_F(SavedAddressLeaseTest, ReleaseCreatesHeader)
{
    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    expect_header(message, RELEASE_MESSAGE_TYPE, 5);
}

TEST_F(SavedAddressLeaseTest, ReleaseCreatesClientIdentifier)
{
    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 5);
    expect_client_identifier(message->option_list[0]);
}

TEST_F(SavedAddressLeaseTest, ReleaseIncludesServerIdentifier)
{
    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 5);
    const auto &server = message->option_list[1];
    EXPECT_EQ(server.option_code, SERVER_ID_OPTION_CODE);
    EXPECT_EQ(server.option_length, 7);
    EXPECT_EQ(server.server_id_t.duid.duid_type, 3);
    EXPECT_EQ(server.server_id_t.duid.hw_type, 1);
    ASSERT_NE(server.server_id_t.duid.mac, nullptr);
    const uint8_t identifier[] = {0xab, 0xcd, 0xef};
    EXPECT_EQ(std::memcmp(server.server_id_t.duid.mac, identifier, sizeof(identifier)), 0);
}

TEST_F(SavedAddressLeaseTest, ReleaseInitializesElapsedTime)
{
    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 5);
    expect_elapsed_time(message->option_list[2]);
}

TEST_F(SavedAddressLeaseTest, ReleaseIncludesAddressLease)
{
    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 5);
    EXPECT_EQ(message->option_list[3].option_code, IA_NA_OPTION_CODE);
    EXPECT_EQ(message->option_list[4].option_code, IA_ADDR_OPTION_CODE);
    EXPECT_TRUE(message->option_list[4].ia_address_t.ipv6_address == address);
}

TEST_F(MessageBuilderTest, ReleaseBuildsDelegatedPrefixLease)
{
    lease_document = R"({"leases":[{
        "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
        "valid_lifetime":1200,"prefix":"2001:db8::/56","prefix_length":56}]})";
    uint8_t requested[] = {DNS_SERVERS_OPTION_CODE};
    config_t config{};
    config.oro_list = requested;
    config.oro_list_length = sizeof(requested);
    config.reconfigure = true;

    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 4);
    expect_header(message, RELEASE_MESSAGE_TYPE, 4);
    EXPECT_EQ(message->option_list[2].option_code, IA_PD_OPTION_CODE);
    EXPECT_EQ(message->option_list[2].ia_pd_t.iaid, 0xdef);
    EXPECT_EQ(message->option_list[3].option_code, IAPREFIX_OPTION_CODE);
    EXPECT_TRUE(message->option_list[3].ia_prefix_t.ipv6_prefix == prefix);
    EXPECT_EQ(message->option_list[3].ia_prefix_t.prefix_length, 56);
}

constexpr char unsupported_lease[] = R"({"leases":[{
    "type":"IATA","iaid":"abc","t1":300,"t2":600,
    "preferred_lifetime":900,"valid_lifetime":1200}]})";

TEST_F(MessageBuilderTest, ConfirmOmitsUnsupportedLeaseType)
{
    lease_document = unsupported_lease;
    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;

    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_client_identifier(message->option_list[0]);
    expect_elapsed_time(message->option_list[1]);
}

TEST_F(MessageBuilderTest, ReleaseOmitsUnsupportedLeaseType)
{
    lease_document = unsupported_lease;
    config_t config{};

    Message message(buildRelease(&config, interface_name), {true});

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->option_count, 2);
    expect_client_identifier(message->option_list[0]);
    expect_elapsed_time(message->option_list[1]);
}

struct InvalidLease {
    const char *name;
    const char *document;
};

std::string invalid_lease_name(const testing::TestParamInfo<InvalidLease> &info)
{
    return info.param.name;
}

class InvalidLeaseBuilderTest : public MessageBuilderTest,
                                public testing::WithParamInterface<InvalidLease> {};

TEST_P(InvalidLeaseBuilderTest, ConfirmRejectsMalformedLease)
{
    lease_document = GetParam().document;
    config_t config{};
    uint32_t t1 = 0, t2 = 0, valid = 0;
    Message message(buildConfirm(&config, interface_name, &t1, &t2, &valid), {true});

    EXPECT_EQ(message, nullptr);
}

TEST_P(InvalidLeaseBuilderTest, ReleaseRejectsMalformedLease)
{
    lease_document = GetParam().document;
    config_t config{};
    Message message(buildRelease(&config, interface_name), {true});

    EXPECT_EQ(message, nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    LeaseDocuments, InvalidLeaseBuilderTest,
    testing::Values(
        InvalidLease{"NonArrayLeases", R"({"leases":{}})"},
        InvalidLease{"MissingType", R"({"leases":[{}]})"},
        InvalidLease{"MissingIaid", R"({"leases":[{"type":"IANA"}]})"},
        InvalidLease{"MissingTimers", R"({"leases":[{"type":"IANA","iaid":"abc"}]})"},
        InvalidLease{"MissingT2", R"({"leases":[{"type":"IANA","iaid":"abc","t1":300}]})"},
        InvalidLease{"MissingPreferredLifetime",
                     R"({"leases":[{"type":"IANA","iaid":"abc","t1":300,"t2":600}]})"},
        InvalidLease{"MissingValidLifetime", R"({"leases":[{
            "type":"IANA","iaid":"abc","t1":300,"t2":600,"preferred_lifetime":900}]})"},
        InvalidLease{"MissingAddress", R"({"leases":[{
            "type":"IANA","iaid":"abc","t1":300,"t2":600,
            "preferred_lifetime":900,"valid_lifetime":1200}]})"},
        InvalidLease{"InvalidAddress", R"({"leases":[{
            "type":"IANA","iaid":"abc","t1":300,"t2":600,
            "preferred_lifetime":900,"valid_lifetime":1200,"address":"not-ipv6"}]})"},
        InvalidLease{"MissingPrefixLength", R"({"leases":[{
            "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
            "valid_lifetime":1200,"prefix":"2001:db8::/56"}]})"},
        InvalidLease{"MissingPrefix", R"({"leases":[{
            "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
            "valid_lifetime":1200,"prefix_length":56}]})"},
        InvalidLease{"EmptyPrefixAddress", R"({"leases":[{
            "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
            "valid_lifetime":1200,"prefix":"/56","prefix_length":56}]})"},
        InvalidLease{"InvalidPrefixAddress", R"({"leases":[{
            "type":"IAPD","iaid":"def","t1":300,"t2":600,"preferred_lifetime":900,
            "valid_lifetime":1200,"prefix":"not-ipv6/56","prefix_length":56}]})"}),
    invalid_lease_name);

class InvalidServerIdentifierTest : public MessageBuilderTest,
                                    public testing::WithParamInterface<InvalidLease> {};

TEST_P(InvalidServerIdentifierTest, ReleaseRejectsInvalidServerIdentifier)
{
    lease_document = GetParam().document;
    config_t config{};
    Message message(buildRelease(&config, interface_name), {true});

    EXPECT_EQ(message, nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    LeaseDocuments, InvalidServerIdentifierTest,
    testing::Values(
        InvalidLease{"MissingDuid", R"({"server_duid":{},"leases":[]})"},
        InvalidLease{"NonHexDigit", R"({"server_duid":{"duid":"00:03:00:01:zz"},"leases":[]})"},
        InvalidLease{"IncompleteOctet", R"({"server_duid":{"duid":"00:03:00:01:1"},"leases":[]})"},
        InvalidLease{"IncorrectSeparator", R"({"server_duid":{"duid":"00-03:00:01:12"},"leases":[]})"},
        InvalidLease{"NoIdentifierPayload", R"({"server_duid":{"duid":"00:03:00:01"},"leases":[]})"}),
    invalid_lease_name);
}
