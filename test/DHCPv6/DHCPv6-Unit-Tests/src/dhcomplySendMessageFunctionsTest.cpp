#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <initializer_list>
#include <string>
#include <vector>

extern "C" {
#include "dhcomplySendMessageFunctions.h"
}

namespace {
struct Transmission {
    int calls = 0;
    int socket = -1;
    std::string interface;
    std::vector<uint8_t> packet;
};

Transmission sent;
bool unexpected_send_is_fatal = false;
}

extern "C" void __wrap_send_dhcpv6_multicast_packet(
    int sockfd, const uint8_t *packet, size_t length, const char *iface_name)
{
    if (unexpected_send_is_fatal) {
        std::_Exit(EXIT_FAILURE);
    }
    ++sent.calls;
    sent.socket = sockfd;
    sent.interface = iface_name;
    sent.packet.assign(packet, packet + length);
}

namespace {
using Send = int (*)(dhcpv6_message_t *, int, const char *, uint32_t);

struct Sender {
    const char *name;
    uint8_t type;
    Send send;
    bool fatal_arguments;
};

constexpr Sender solicit{"Solicit", SOLICIT_MESSAGE_TYPE, sendSolicit, true};
constexpr Sender request{"Request", REQUEST_MESSAGE_TYPE, sendRequest, true};
constexpr Sender renew{"Renew", RENEW_MESSAGE_TYPE, sendRenew, true};
constexpr Sender rebind{"Rebind", REBIND_MESSAGE_TYPE, sendRebind, true};
constexpr Sender decline{"Decline", DECLINE_MESSAGE_TYPE, sendDecline, true};
constexpr Sender information_request{
    "InformationRequest", INFORMATION_REQUEST_MESSAGE_TYPE, sendInformationRequest, true};
constexpr Sender confirm{"Confirm", CONFIRM_MESSAGE_TYPE, sendConfirm, false};
constexpr Sender release{"Release", RELEASE_MESSAGE_TYPE, sendRelease, false};

std::string sender_name(const testing::TestParamInfo<Sender> &info)
{
    return info.param.name;
}

class SenderTest : public testing::Test {
protected:
    static constexpr int socket_fd = 19;
    static constexpr const char *interface_name = "test0";

    void SetUp() override
    {
        sent = {};
        unexpected_send_is_fatal = false;
    }

    dhcpv6_message_t message(uint8_t type, dhcpv6_option_t *options, uint8_t count)
    {
        dhcpv6_message_t result{};
        result.message_type = type;
        result.transaction_id = 0x12abef;
        result.option_list = options;
        result.option_count = count;
        return result;
    }

    void expect_wire_packet(const Sender &sender, dhcpv6_option_t *options, uint8_t count,
                            std::initializer_list<uint8_t> payload, uint32_t elapsed = 0)
    {
        auto msg = message(sender.type, options, count);
        ASSERT_EQ(sender.send(&msg, socket_fd, interface_name, elapsed), 0);
        std::vector<uint8_t> expected{sender.type, 0x12, 0xab, 0xef};
        expected.insert(expected.end(), payload);
        EXPECT_EQ(sent.packet, expected);
    }
};

class PacketSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(PacketSenderTest, SerializesClientIdentifier)
{
    uint8_t mac[] = {0x02, 0x13, 0x24, 0x35, 0x46, 0x57};
    dhcpv6_option_t option{};
    option.option_code = CLIENT_ID_OPTION_CODE;
    option.option_length = 10;
    option.client_id_t.duid = {3, 1, mac};
    expect_wire_packet(GetParam(), &option, 1,
                       {0, 1, 0, 10, 0, 3, 0, 1, 0x02, 0x13, 0x24, 0x35, 0x46, 0x57});
}

TEST_P(PacketSenderTest, SerializesElapsedTime)
{
    dhcpv6_option_t option{};
    option.option_code = ELAPSED_TIME_OPTION_CODE;
    option.option_length = 2;
    expect_wire_packet(GetParam(), &option, 1, {0, 8, 0, 2, 0xab, 0xcd}, 0xabcd);
}

TEST_P(PacketSenderTest, SendsOnceThroughSuppliedSocketAndInterface)
{
    const Sender &sender = GetParam();
    auto msg = message(sender.type, nullptr, 0);

    ASSERT_EQ(sender.send(&msg, socket_fd, interface_name, 0), 0);

    EXPECT_EQ(sent.calls, 1);
    EXPECT_EQ(sent.socket, socket_fd);
    EXPECT_EQ(sent.interface, interface_name);
}

TEST_P(PacketSenderTest, OmitsReservedZeroLengthOption)
{
    dhcpv6_option_t option{};
    expect_wire_packet(GetParam(), &option, 1, {});
}

TEST_P(PacketSenderTest, RejectsNullMessage)
{
    const Sender &sender = GetParam();
    if (sender.fatal_arguments) {
        EXPECT_EXIT({
            unexpected_send_is_fatal = true;
            sender.send(nullptr, socket_fd, interface_name, 0);
        }, testing::ExitedWithCode(255), "");
    } else {
        EXPECT_EQ(sender.send(nullptr, socket_fd, interface_name, 0), -1);
    }
    EXPECT_EQ(sent.calls, 0);
}

TEST_P(PacketSenderTest, RejectsInvalidSocket)
{
    const Sender &sender = GetParam();
    auto msg = message(sender.type, nullptr, 0);
    if (sender.fatal_arguments) {
        EXPECT_EXIT({
            unexpected_send_is_fatal = true;
            sender.send(&msg, -1, interface_name, 0);
        }, testing::ExitedWithCode(255), "");
    } else {
        EXPECT_EQ(sender.send(&msg, -1, interface_name, 0), -1);
    }
    EXPECT_EQ(sent.calls, 0);
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, PacketSenderTest,
    testing::Values(solicit, request, renew, rebind, decline, information_request, confirm, release),
    sender_name);

TEST_P(PacketSenderTest, SerializesUnknownZeroLengthOptionHeader)
{
    dhcpv6_option_t option{};
    option.option_code = 0xf123;
    expect_wire_packet(GetParam(), &option, 1, {0xf1, 0x23, 0, 0});
}

TEST_F(SenderTest, RequestOmitsPreferenceBeforeElapsedTime)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = PREFERENCE_OPTION_CODE;
    options[0].option_length = 1;
    options[0].preference_t.preference_value = 90;
    options[1].option_code = ELAPSED_TIME_OPTION_CODE;
    options[1].option_length = 2;
    expect_wire_packet(request, options.data(), options.size(), {0, 8, 0, 2, 0, 0});
}

TEST_F(SenderTest, RequestOmitsSolMaxRtBeforeElapsedTime)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = SOL_MAX_RT_OPTION_CODE;
    options[0].option_length = 4;
    options[0].SOL_MAX_RT_t.SOL_MAX_RT_value = 120;
    options[1].option_code = ELAPSED_TIME_OPTION_CODE;
    options[1].option_length = 2;
    expect_wire_packet(request, options.data(), options.size(), {0, 8, 0, 2, 0, 0});
}

TEST_P(PacketSenderTest, OmitsReservedOptionCodeWithNonzeroLength)
{
    dhcpv6_option_t option{};
    option.option_length = 8;
    expect_wire_packet(GetParam(), &option, 1, {});
}

TEST_F(SenderTest, SolicitSerializesRapidCommit)
{
    dhcpv6_option_t option{};
    option.option_code = RAPID_COMMIT_OPTION_CODE;
    expect_wire_packet(solicit, &option, 1, {0, 14, 0, 0});
}

TEST_F(SenderTest, SolicitSerializesReconfigureAccept)
{
    dhcpv6_option_t option{};
    option.option_code = RECONF_ACCEPT_OPTION_CODE;
    expect_wire_packet(solicit, &option, 1, {0, 20, 0, 0});
}

class OptionRequestSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(OptionRequestSenderTest, SerializesRequestedOptionCodesInNetworkOrder)
{
    uint8_t requested_codes[] = {DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE};
    dhcpv6_option_t option{};
    option.option_code = ORO_OPTION_CODE;
    option.option_length = 4;
    option.option_request_t.option_request = requested_codes;
    expect_wire_packet(GetParam(), &option, 1, {0, 6, 0, 4, 0, 23, 0, 24});
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, OptionRequestSenderTest,
    testing::Values(solicit, request, renew, rebind, decline, information_request, confirm),
    sender_name);

TEST_F(SenderTest, RebindOmitsServerIdentifier)
{
    uint8_t server_mac[] = {0x02, 0x13, 0x24, 0x35, 0x46, 0x57};
    dhcpv6_option_t option{};
    option.option_code = SERVER_ID_OPTION_CODE;
    option.option_length = 10;
    option.server_id_t.duid = {3, 1, server_mac};
    auto msg = message(REBIND_MESSAGE_TYPE, &option, 1);

    ASSERT_EQ(sendRebind(&msg, socket_fd, interface_name, 0), 0);

    const std::vector<uint8_t> expected{REBIND_MESSAGE_TYPE, 0x12, 0xab, 0xef};
    EXPECT_EQ(sent.packet, expected);
}

class AddressSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(AddressSenderTest, SerializesIdentityAssociationAndNestedAddress)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_NA_OPTION_CODE;
    options[0].option_length = 40;
    options[0].ia_na_t.iaid = 0x01020304;
    options[0].ia_na_t.t1 = 0x0102;
    options[0].ia_na_t.t2 = 0x0304;
    options[1].option_code = IA_ADDR_OPTION_CODE;
    options[1].option_length = 24;
    options[1].ia_address_t.ipv6_address =
        (static_cast<uint128_t>(0x20010db8) << 96) | 0xabcd;
    options[1].ia_address_t.preferred_lifetime = 0x0506;
    options[1].ia_address_t.valid_lifetime = 0x0708;
    expect_wire_packet(GetParam(), options.data(), options.size(), {
        0, 3, 0, 40, 1, 2, 3, 4, 0, 0, 1, 2, 0, 0, 3, 4,
        0, 5, 0, 24,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd,
        0, 0, 5, 6, 0, 0, 7, 8,
    });
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, AddressSenderTest,
    testing::Values(solicit, request, renew, rebind, decline, confirm, release), sender_name);

class PrefixSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(PrefixSenderTest, SerializesIdentityAssociationAndNestedPrefix)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_PD_OPTION_CODE;
    options[0].option_length = 41;
    options[0].ia_pd_t.iaid = 0x01020304;
    options[0].ia_pd_t.t1 = 0x0102;
    options[0].ia_pd_t.t2 = 0x0304;
    options[1].option_code = IAPREFIX_OPTION_CODE;
    options[1].option_length = 25;
    options[1].ia_prefix_t.prefix_length = 56;
    options[1].ia_prefix_t.preferred_lifetime = 0x0506;
    options[1].ia_prefix_t.valid_lifetime = 0x0708;
    options[1].ia_prefix_t.ipv6_prefix = static_cast<uint128_t>(0x20010db8) << 96;
    expect_wire_packet(GetParam(), options.data(), options.size(), {
        0, 25, 0, 41, 1, 2, 3, 4, 0, 0, 1, 2, 0, 0, 3, 4,
        0, 26, 0, 25,
        0, 0, 5, 6, 0, 0, 7, 8, 56,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    });
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, PrefixSenderTest,
    testing::Values(solicit, request, renew, rebind, confirm, release), sender_name);

class ServerIdentifierSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(ServerIdentifierSenderTest, SerializesVariableLengthServerIdentifier)
{
    uint8_t identifier[] = {0x12, 0x34, 0x56};
    dhcpv6_option_t option{};
    option.option_code = SERVER_ID_OPTION_CODE;
    option.option_length = 7;
    option.server_id_t.duid = {3, 1, identifier};
    expect_wire_packet(GetParam(), &option, 1, {0, 2, 0, 7, 0, 3, 0, 1, 0x12, 0x34, 0x56});
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, ServerIdentifierSenderTest,
    testing::Values(request, renew, decline, confirm, release), sender_name);

class DnsOptionSenderTest : public SenderTest, public testing::WithParamInterface<Sender> {};

TEST_P(DnsOptionSenderTest, SerializesDnsServerAddress)
{
    uint8_t server[] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    dhcpv6_option_t option{};
    option.option_code = DNS_SERVERS_OPTION_CODE;
    option.option_length = sizeof(server);
    option.dns_recursive_name_server_t.dns_servers = server;
    expect_wire_packet(GetParam(), &option, 1, {
        0, 23, 0, 16, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    });
}

TEST_P(DnsOptionSenderTest, SerializesDomainSearchListWithEmbeddedLengthBytes)
{
    char domain[] = {1, 'a', 4, 't', 'e', 's', 't', 0};
    dhcpv6_option_t option{};
    option.option_code = DOMAIN_SEARCH_LIST_OPTION_CODE;
    option.option_length = sizeof(domain);
    option.domain_search_list_t.search_list = domain;
    expect_wire_packet(GetParam(), &option, 1, {
        0, 24, 0, 8, 1, 'a', 4, 't', 'e', 's', 't', 0,
    });
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, DnsOptionSenderTest,
    testing::Values(request, renew, rebind, decline, confirm), sender_name);

TEST_F(SenderTest, SolicitSerializesBarePrefixAssociationBeforeAddressAssociation)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_PD_OPTION_CODE;
    options[0].option_length = 12;
    options[0].ia_pd_t.iaid = 0x01020304;
    options[1].option_code = IA_NA_OPTION_CODE;
    options[1].option_length = 12;
    options[1].ia_na_t.iaid = 0x05060708;
    expect_wire_packet(solicit, options.data(), options.size(), {
        0, 25, 0, 12, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3, 0, 12, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0,
    });
}

TEST_F(SenderTest, SolicitSerializesAddressAssociationBeforeBarePrefixAssociation)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_NA_OPTION_CODE;
    options[0].option_length = 12;
    options[0].ia_na_t.iaid = 1;
    options[1].option_code = IA_PD_OPTION_CODE;
    options[1].option_length = 12;
    options[1].ia_pd_t.iaid = 2;
    expect_wire_packet(solicit, options.data(), options.size(), {
        0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 25, 0, 12, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
    });
}

TEST_F(SenderTest, DeclineLeavesAdjacentIdentityAssociationsSeparate)
{
    std::array<dhcpv6_option_t, 2> options{};
    options[0].option_code = IA_NA_OPTION_CODE;
    options[0].option_length = 12;
    options[0].ia_na_t.iaid = 1;
    options[1].option_code = IA_NA_OPTION_CODE;
    options[1].option_length = 12;
    options[1].ia_na_t.iaid = 2;
    expect_wire_packet(decline, options.data(), options.size(), {
        0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3, 0, 12, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
    });
}

TEST_F(SenderTest, DeclineSerializesStandaloneAddressPayload)
{
    dhcpv6_option_t option{};
    option.option_code = IA_ADDR_OPTION_CODE;
    option.option_length = 24;
    option.ia_address_t.ipv6_address =
        (static_cast<uint128_t>(0x20010db8) << 96) | 0xabcd;
    option.ia_address_t.preferred_lifetime = 0x0102;
    option.ia_address_t.valid_lifetime = 0x0304;
    expect_wire_packet(decline, &option, 1, {
        0, 5, 0, 24,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd,
        0, 0, 1, 2, 0, 0, 3, 4,
    });
}
}
