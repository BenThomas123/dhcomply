#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include "dhcomplyParseMessageFunctions.h"
}

namespace {
using Packet = std::vector<uint8_t>;

constexpr uint32_t transaction_id = 0x123456;
constexpr char interface_name[] = "test0";
constexpr uint128_t address = (static_cast<uint128_t>(0x20010db8u) << 96) | 0x42u;
constexpr uint128_t prefix = (static_cast<uint128_t>(0x20010db8u) << 96);

struct WrittenLease {
    int calls = 0;
    bool has_address = false;
    bool has_prefix = false;
    std::string interface;
    std::string address;
    uint8_t prefix_length = 0;
    size_t duid_length = 0;
};

WrittenLease written_lease;
std::vector<std::string> commands;
bool fail_dns_address_allocation = false;

void add_option(Packet &packet, uint8_t code, std::initializer_list<uint8_t> value)
{
    packet.insert(packet.end(), {0, code, 0, static_cast<uint8_t>(value.size())});
    packet.insert(packet.end(), value);
}

void add_address(Packet &packet, uint8_t preferred_lifetime = 60, uint8_t valid_lifetime = 90,
                 uint8_t t2 = 30)
{
    add_option(packet, IA_NA_OPTION_CODE, {
        1, 2, 3, 4, 0, 0, 0, 20, 0, 0, 0, t2,
        0, IA_ADDR_OPTION_CODE, 0, 24,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
        0, 0, 0, preferred_lifetime, 0, 0, 0, valid_lifetime,
    });
}

void add_prefix(Packet &packet, uint8_t preferred_lifetime = 60, uint8_t valid_lifetime = 90,
                uint8_t t2 = 30)
{
    add_option(packet, IA_PD_OPTION_CODE, {
        4, 3, 2, 1, 0, 0, 0, 20, 0, 0, 0, t2,
        0, IAPREFIX_OPTION_CODE, 0, 25,
        0, 0, 0, preferred_lifetime, 0, 0, 0, valid_lifetime, 64,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    });
}

void add_dns_server(Packet &packet)
{
    add_option(packet, DNS_SERVERS_OPTION_CODE, {
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
    });
}

constexpr uint8_t encoded_domains[]{
    3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
    3, 'l', 'a', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
};

void add_domains(Packet &packet)
{
    packet.insert(packet.end(), {0, DOMAIN_SEARCH_LIST_OPTION_CODE, 0, sizeof(encoded_domains)});
    packet.insert(packet.end(), encoded_domains, encoded_domains + sizeof(encoded_domains));
}

struct AssociationStatus {
    bool address;
    uint8_t status;
};

void add_association_status(Packet &packet, AssociationStatus association)
{
    const size_t start = packet.size();
    if (association.address) {
        add_address(packet);
    } else {
        add_prefix(packet);
    }
    constexpr size_t nested_option_code = 17;
    constexpr size_t nested_option_length = 19;
    constexpr size_t nested_payload = 20;
    packet[start + nested_option_code] = STATUS_CODE_OPTION_CODE;
    // Include a diagnostic string in the nested status option.
    const size_t length = packet[start + nested_option_length];
    packet[start + nested_payload] = 0;
    packet[start + nested_payload + 1] = association.status;
    for (size_t i = 2; i < length; ++i) {
        packet[start + nested_payload + i] = 'x';
    }
}

void prepend_association_suboption(Packet &packet, size_t association_start, uint8_t code,
                                   std::initializer_list<uint8_t> value)
{
    Packet option;
    add_option(option, code, value);
    packet[association_start + 3] += static_cast<uint8_t>(option.size());
    packet.insert(packet.begin() + association_start + 16, option.begin(), option.end());
}

struct FreeMessage {
    void operator()(dhcpv6_message_t *message) const
    {
        for (size_t i = 0; i < message->option_count; ++i) {
            auto &option = message->option_list[i];
            switch (option.option_code) {
                case CLIENT_ID_OPTION_CODE:
                    std::free(option.client_id_t.duid.mac);
                    break;
                case SERVER_ID_OPTION_CODE:
                    std::free(option.server_id_t.duid.mac);
                    break;
                case DNS_SERVERS_OPTION_CODE:
                    std::free(option.dns_recursive_name_server_t.dns_servers);
                    break;
                case DOMAIN_SEARCH_LIST_OPTION_CODE:
                    std::free(option.domain_search_list_t.search_list);
                    break;
                default:
                    break;
            }
        }
        std::free(message->option_list);
        std::free(message);
    }
};

using Message = std::unique_ptr<dhcpv6_message_t, FreeMessage>;

class ParseMessageTest : public testing::Test {
protected:
    void SetUp() override
    {
        written_lease = {};
        commands.clear();
        fail_dns_address_allocation = false;
        request.message_type = REQUEST_MESSAGE_TYPE;
        request.transaction_id = transaction_id;
        request.option_count = 1;
        request.option_list = &client_id;
        client_id.option_code = CLIENT_ID_OPTION_CODE;
        client_id.client_id_t.duid = {3, 1, mac};
    }

    Packet with_identifiers(uint8_t message_type)
    {
        Packet packet{message_type, 0x12, 0x34, 0x56};
        add_option(packet, CLIENT_ID_OPTION_CODE, {0, 3, 0, 1, 1, 2, 3, 4, 5, 6});
        add_option(packet, SERVER_ID_OPTION_CODE, {0, 3, 0, 1, 6, 5, 4, 3, 2, 1});
        return packet;
    }

    uint8_t mac[6]{1, 2, 3, 4, 5, 6};
    dhcpv6_option_t client_id{};
    dhcpv6_message_t request{};
};
}

extern "C" void __wrap_execute_formatted_command(const char *command, size_t capacity, int length)
{
    if (length >= 0 && static_cast<size_t>(length) < capacity) {
        commands.emplace_back(command);
    }
}

extern "C" char *__real_append_ipv6_address_if_unique(const char *, const char *);

extern "C" char *__wrap_append_ipv6_address_if_unique(const char *addresses, const char *address)
{
    if (fail_dns_address_allocation) {
        fail_dns_address_allocation = false;
        errno = ENOMEM;
        return nullptr;
    }
    return __real_append_ipv6_address_if_unique(addresses, address);
}

extern "C" int __wrap_writeLease(IANA_t *iana, IAPD_t *iapd, const char *iface,
                                  const duid_ll_t *duid, size_t duid_length)
{
    ++written_lease.calls;
    written_lease.has_address = iana != nullptr;
    written_lease.has_prefix = iapd != nullptr;
    written_lease.interface = iface;
    if (iana) {
        written_lease.address = iana->address;
    }
    if (iapd) {
        written_lease.prefix_length = iapd->prefix_length;
    }
    written_lease.duid_length = duid ? duid_length : 0;
    return 0;
}

namespace {
TEST_F(ParseMessageTest, AdvertisementDecodesHeader)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_EQ(message->transaction_id, transaction_id);
    EXPECT_EQ(message->message_type, ADVERTISE_MESSAGE_TYPE);
}

TEST_F(ParseMessageTest, AdvertisementDecodesAddress)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[2].ia_na_t.iaid, 0x01020304u);
    EXPECT_EQ(message->option_list[3].ia_address_t.ipv6_address, address);
    EXPECT_EQ(message->option_list[3].ia_address_t.preferred_lifetime, 60u);
}

TEST_F(ParseMessageTest, AdvertisementDecodesPreference)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_option(packet, PREFERENCE_OPTION_CODE, {200});

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 5);
    EXPECT_EQ(message->option_list[4].preference_t.preference_value, 200u);
}

TEST_F(ParseMessageTest, AdvertisementDecodesDelegatedPrefix)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_prefix(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[2].ia_pd_t.iaid, 0x04030201u);
    EXPECT_EQ(message->option_list[3].ia_prefix_t.ipv6_prefix, prefix);
    EXPECT_EQ(message->option_list[3].ia_prefix_t.prefix_length, 64u);
}

TEST_F(ParseMessageTest, AdvertisementRejectsWrongTransactionId)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    ++request.transaction_id;

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

enum class ClientDifference { type, hardware, mac };

class ClientIdentifierMismatchTest : public ParseMessageTest,
                                     public testing::WithParamInterface<ClientDifference> {
protected:
    void mismatch()
    {
        switch (GetParam()) {
            case ClientDifference::type:
                ++client_id.client_id_t.duid.duid_type;
                break;
            case ClientDifference::hardware:
                ++client_id.client_id_t.duid.hw_type;
                break;
            case ClientDifference::mac:
                ++mac[0];
                break;
        }
    }
};

TEST_P(ClientIdentifierMismatchTest, AdvertisementRejectsDifferentClientIdentifier)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    mismatch();

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_P(ClientIdentifierMismatchTest, StatefulReplyRejectsDifferentClientIdentifier)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    request.message_type = CONFIRM_MESSAGE_TYPE;
    mismatch();

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_P(ClientIdentifierMismatchTest, StatelessReplyRejectsDifferentClientIdentifier)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
    mismatch();

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

INSTANTIATE_TEST_SUITE_P(DuidFields, ClientIdentifierMismatchTest,
                         testing::Values(ClientDifference::type, ClientDifference::hardware,
                                         ClientDifference::mac),
                         [](const testing::TestParamInfo<ClientDifference> &info) {
                             switch (info.param) {
                                 case ClientDifference::type: return "Type";
                                 case ClientDifference::hardware: return "Hardware";
                                 case ClientDifference::mac: return "Mac";
                             }
                             return "UnknownField";
                         });

enum class Parser { advertisement, stateful, stateless };

class ClientIdentifierLookupTest : public ParseMessageTest,
                                   public testing::WithParamInterface<Parser> {
protected:
    Message parse()
    {
        if (GetParam() == Parser::advertisement) {
            Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
            add_address(packet);
            return Message(parseAdvertisement(packet.data(), &request, packet.size()));
        }
        Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
        if (GetParam() == Parser::stateful) {
            request.message_type = CONFIRM_MESSAGE_TYPE;
            return Message(parseReply(packet.data(), &request, interface_name, packet.size()));
        }
        request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
        return Message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));
    }
};

TEST_P(ClientIdentifierLookupTest, AcceptsClientIdentifierAtDifferentRequestOffset)
{
    dhcpv6_option_t options[2]{};
    options[0].option_code = ELAPSED_TIME_OPTION_CODE;
    options[1] = client_id;
    request.option_list = options;
    request.option_count = 2;

    Message message = parse();

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_P(ClientIdentifierLookupTest, RejectsRequestWithNoClientIdentifier)
{
    client_id.option_code = ELAPSED_TIME_OPTION_CODE;

    Message message = parse();

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

INSTANTIATE_TEST_SUITE_P(MessageParsers, ClientIdentifierLookupTest,
                         testing::Values(Parser::advertisement, Parser::stateful, Parser::stateless),
                         [](const testing::TestParamInfo<Parser> &info) {
                             switch (info.param) {
                                 case Parser::advertisement: return "Advertisement";
                                 case Parser::stateful: return "StatefulReply";
                                 case Parser::stateless: return "StatelessReply";
                             }
                             return "UnknownParser";
                         });

class AssociationFailureTest : public ParseMessageTest,
                               public testing::WithParamInterface<AssociationStatus> {};

TEST_P(AssociationFailureTest, AdvertisementRejectsNestedFailure)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_association_status(packet, GetParam());

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_P(AssociationFailureTest, ReplyRejectsNestedFailure)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_association_status(packet, GetParam());

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

INSTANTIATE_TEST_SUITE_P(IdentityAssociations, AssociationFailureTest,
                         testing::Values(AssociationStatus{true, NOADDRAVAIL_STATUS_CODE},
                                         AssociationStatus{false, NOPREFIXAVAIL_STATUS_CODE}),
                         [](const testing::TestParamInfo<AssociationStatus> &info) {
                             return info.param.address ? "Address" : "Prefix";
                         });

class AssociationSuccessTest : public ParseMessageTest, public testing::WithParamInterface<bool> {
protected:
    void add_association_with_success(Packet &packet) const
    {
        size_t start = packet.size();
        if (GetParam()) {
            add_address(packet);
        } else {
            add_prefix(packet);
        }
        prepend_association_suboption(packet, start, STATUS_CODE_OPTION_CODE, {0, 0});
    }
};

TEST_P(AssociationSuccessTest, AdvertisementFindsLeaseAfterSuccessStatus)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_association_with_success(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 4);
    if (GetParam()) {
        EXPECT_EQ(message->option_list[3].option_code, IA_ADDR_OPTION_CODE);
        EXPECT_EQ(message->option_list[3].ia_address_t.ipv6_address, address);
    } else {
        EXPECT_EQ(message->option_list[3].option_code, IAPREFIX_OPTION_CODE);
        EXPECT_EQ(message->option_list[3].ia_prefix_t.ipv6_prefix, prefix);
    }
}

TEST_P(AssociationSuccessTest, ReplyPersistsLeaseAfterSuccessStatus)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_association_with_success(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_EQ(written_lease.calls, 1);
    EXPECT_EQ(written_lease.has_address, GetParam());
    EXPECT_EQ(written_lease.has_prefix, !GetParam());
    if (GetParam()) {
        EXPECT_EQ(written_lease.address, "2001:db8::42");
    } else {
        EXPECT_EQ(written_lease.prefix_length, 64);
    }
}

INSTANTIATE_TEST_SUITE_P(IdentityAssociations, AssociationSuccessTest,
                         testing::Bool(),
                         [](const testing::TestParamInfo<bool> &info) {
                             return info.param ? "Address" : "Prefix";
                         });

TEST_F(ParseMessageTest, ReplyRejectsTruncatedIdentityAssociation)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t start = packet.size();
    add_address(packet);
    ++packet[start + 3];
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyRejectsTruncatedAssociationChild)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t start = packet.size();
    add_address(packet);
    ++packet[start + 19];
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyRejectsShortNestedStatus)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t start = packet.size();
    add_address(packet);
    prepend_association_suboption(packet, start, STATUS_CODE_OPTION_CODE, {0});
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyRejectsNestedStatusWithOnlyHighByteSet)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t start = packet.size();
    add_address(packet);
    prepend_association_suboption(packet, start, STATUS_CODE_OPTION_CODE, {1, 0});
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyRejectsAddressChildTooShortForLease)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, IA_NA_OPTION_CODE, {
        1, 2, 3, 4, 0, 0, 0, 20, 0, 0, 0, 30,
        0, IA_ADDR_OPTION_CODE, 0, 1, 0x20,
    });
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyRejectsTrailingPartialAssociationSuboption)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t start = packet.size();
    add_address(packet);
    ++packet[start + 3];
    packet.push_back(0);
    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, AdvertisementIgnoresOtherOptionalFields)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_option(packet, RECONF_ACCEPT_OPTION_CODE, {});
    add_option(packet, ELAPSED_TIME_OPTION_CODE, {0, 10});

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_F(ParseMessageTest, AdvertisementRejectsMissingIdentityAssociation)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, AdvertisementRejectsFailureStatus)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, UNSPECFAIL_STATUS_CODE});

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, AdvertisementCopiesDnsServerBytes)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_dns_server(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 5);
    const auto &dns = message->option_list[4];
    ASSERT_EQ(dns.option_length, 16);
    ASSERT_NE(dns.dns_recursive_name_server_t.dns_servers, nullptr);
    EXPECT_EQ(dns.dns_recursive_name_server_t.dns_servers[0], 0x20);
    EXPECT_EQ(dns.dns_recursive_name_server_t.dns_servers[15], 0x53);
}

TEST_F(ParseMessageTest, AdvertisementLeavesDnsConfigurationAlone)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_dns_server(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, AdvertisementCopiesEncodedDomainSearchList)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_domains(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 5);
    const auto &domains = message->option_list[4];
    ASSERT_EQ(domains.option_length, sizeof(encoded_domains));
    EXPECT_EQ(std::memcmp(domains.domain_search_list_t.search_list, encoded_domains,
                          sizeof(encoded_domains)), 0);
}

TEST_F(ParseMessageTest, AdvertisementLeavesSearchDomainConfigurationAlone)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_domains(packet);

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, AdvertisementDecodesSolicitMaximumRetransmitTime)
{
    Packet packet = with_identifiers(ADVERTISE_MESSAGE_TYPE);
    add_address(packet);
    add_option(packet, SOL_MAX_RT_OPTION_CODE, {0, 0, 0, 120});

    Message message(parseAdvertisement(packet.data(), &request, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_EQ(message->option_list[4].SOL_MAX_RT_t.SOL_MAX_RT_value, 120u);
}

TEST_F(ParseMessageTest, ReplyAcceptsConfirmWithMatchingIdentifiers)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyRejectsWrongTransactionId)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    request.message_type = CONFIRM_MESSAGE_TYPE;
    ++request.transaction_id;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, ConfirmReplyRequiresBothIdentifiers)
{
    Packet packet{REPLY_MESSAGE_TYPE, 0x12, 0x34, 0x56};
    request.message_type = CONFIRM_MESSAGE_TYPE;
    add_option(packet, CLIENT_ID_OPTION_CODE, {0, 3, 0, 1, 1, 2, 3, 4, 5, 6});

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, RequestReplyRejectsMissingIdentityAssociation)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, ReplyReportsNotOnLink)
{
    Packet packet{REPLY_MESSAGE_TYPE, 0x12, 0x34, 0x56};
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, NOTONLINK_STATUS_CODE});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    EXPECT_EQ(parseReply(packet.data(), &request, interface_name, packet.size()), nullptr);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyPersistsAddressLease)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_EQ(written_lease.calls, 1);
    EXPECT_TRUE(written_lease.has_address);
    EXPECT_FALSE(written_lease.has_prefix);
    EXPECT_EQ(written_lease.interface, interface_name);
    EXPECT_EQ(written_lease.address, "2001:db8::42");
    EXPECT_EQ(written_lease.duid_length, MAC_ADDRESS_LENGTH);
}

TEST_F(ParseMessageTest, ReplyAppliesLeasedAddressToInterface)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(commands.size(), 2u);
    EXPECT_NE(commands[1].find("addr add 2001:db8::42/128"), std::string::npos);
}

TEST_F(ParseMessageTest, ReplyPersistsDelegatedPrefixLease)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_EQ(written_lease.calls, 1);
    EXPECT_FALSE(written_lease.has_address);
    EXPECT_TRUE(written_lease.has_prefix);
    EXPECT_EQ(written_lease.prefix_length, 64u);
}

TEST_F(ParseMessageTest, PrefixOnlyReplyLeavesInterfaceAddressesAlone)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyPersistsBothKindsOfLease)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    add_prefix(packet);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    EXPECT_EQ(written_lease.calls, 1);
    EXPECT_TRUE(written_lease.has_address);
    EXPECT_TRUE(written_lease.has_prefix);
}

TEST_F(ParseMessageTest, ReplyRejectsInvertedAddressLifetimes)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet, 90, 60);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyAcceptsRapidCommitOptionDuringSolicit)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    add_option(packet, RAPID_COMMIT_OPTION_CODE, {});
    dhcpv6_option_t request_options[2]{client_id};
    request_options[1].option_code = RAPID_COMMIT_OPTION_CODE;
    request.option_list = request_options;
    request.option_count = 2;
    request.message_type = SOLICIT_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_F(ParseMessageTest, ReplyRejectsOmittedRequestedRapidCommit)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    dhcpv6_option_t request_options[2]{client_id};
    request_options[1].option_code = RAPID_COMMIT_OPTION_CODE;
    request.option_list = request_options;
    request.option_count = 2;
    request.message_type = SOLICIT_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyRejectsUnspecifiedFailureStatus)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, UNSPECFAIL_STATUS_CODE});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyDoesNotAddAddressWhenReleasing)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    request.message_type = RELEASE_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_NE(commands[0].find("addr del 2001:db8::42/128"), std::string::npos);
}

TEST_F(ParseMessageTest, ReleaseReplyAcceptsSuccessfulStatusWithoutAssociation)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, 0});
    request.message_type = RELEASE_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_F(ParseMessageTest, SuccessfulReleaseReplySkipsLeaseWrite)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, 0});
    request.message_type = RELEASE_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, SuccessfulReleaseReplySkipsInterfaceConfiguration)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, 0});
    request.message_type = RELEASE_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(commands.empty());
}

TEST_F(ParseMessageTest, ReplyConfiguresDnsServers)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands[0], "sudo resolvectl dns test0 2001:db8::53\n");
}

TEST_F(ParseMessageTest, ReplyConfiguresMultipleSearchDomains)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_domains(packet);
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands[0], "sudo resolvectl domain test0 www.example lab.example\n");
}

TEST_F(ParseMessageTest, ReplyDecodesSolicitMaximumRetransmitTime)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, SOL_MAX_RT_OPTION_CODE, {0, 0, 0, 120});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_EQ(message->option_list[2].SOL_MAX_RT_t.SOL_MAX_RT_value, 120u);
}

TEST_F(ParseMessageTest, ReplyDecodesPreference)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, PREFERENCE_OPTION_CODE, {17});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].preference_t.preference_value, 17);
}

TEST_F(ParseMessageTest, ReplyToleratesUnrecognizedElapsedTimeOption)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, ELAPSED_TIME_OPTION_CODE, {0, 10});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_F(ParseMessageTest, RenewReplyRejectsDifferentAddress)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    dhcpv6_option_t request_options[4]{client_id};
    request_options[3].option_code = IA_ADDR_OPTION_CODE;
    request_options[3].ia_address_t.ipv6_address = address + 1;
    request.option_list = request_options;
    request.option_count = 4;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, RenewReplyRejectsDifferentPrefix)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);
    dhcpv6_option_t request_options[4]{client_id};
    request_options[3].option_code = IAPREFIX_OPTION_CODE;
    request_options[3].ia_prefix_t.ipv6_prefix = prefix + 1;
    request.option_list = request_options;
    request.option_count = 4;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, ReplyRejectsPrefixT2EarlierThanT1)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    const size_t association_start = packet.size();
    add_prefix(packet);
    constexpr size_t t2_low_byte = 15;
    packet[association_start + t2_low_byte] = 10;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, StatelessReplyDecodesRefreshTime)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, INFORMATION_REFRESH_OPTION_CODE, {0, 0, 0x0e, 0x10});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].information_refresh_time_t.information_refresh_time, 3600u);
}

TEST_F(ParseMessageTest, StatelessReplyRejectsWrongTransactionId)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
    ++request.transaction_id;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, StatelessReplyRejectsMissingIdentifiers)
{
    Packet packet{REPLY_MESSAGE_TYPE, 0x12, 0x34, 0x56};
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, StatelessReplyConfiguresDnsServers)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands[0], "sudo resolvectl dns test0 2001:db8::53\n");
}

TEST_F(ParseMessageTest, StatelessReplyConfiguresMultipleSearchDomains)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_domains(packet);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands[0], "sudo resolvectl domain test0 www.example lab.example\n");
}

TEST_F(ParseMessageTest, StatelessReplyDecodesInformationMaximumRetransmitTime)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, INF_MAX_RT_OPTION_CODE, {0, 0, 1, 44});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_EQ(message->option_list[2].INF_MAX_RT_t.INF_MAX_RT_value, 300u);
}

TEST_F(ParseMessageTest, StatelessReplyRejectsFailureStatus)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, UNSPECFAIL_STATUS_CODE});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
}

TEST_F(ParseMessageTest, StatelessReplyDecodesPreference)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, PREFERENCE_OPTION_CODE, {17});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    ASSERT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].preference_t.preference_value, 17);
}

TEST_F(ParseMessageTest, StatelessReplyToleratesUnrecognizedElapsedTimeOption)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, ELAPSED_TIME_OPTION_CODE, {0, 10});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

class ReplyFamilyTest : public ParseMessageTest, public testing::WithParamInterface<Parser> {
protected:
    uint8_t message_type() const
    {
        return GetParam() == Parser::advertisement ? ADVERTISE_MESSAGE_TYPE : REPLY_MESSAGE_TYPE;
    }

    Message parse(Packet &packet)
    {
        switch (GetParam()) {
            case Parser::advertisement:
                request.message_type = SOLICIT_MESSAGE_TYPE;
                return Message(parseAdvertisement(packet.data(), &request, packet.size()));
            case Parser::stateful:
                return Message(parseReply(packet.data(), &request, interface_name, packet.size()));
            case Parser::stateless:
                request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
                return Message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));
        }
        return {};
    }
};

TEST_P(ReplyFamilyTest, AcceptsSuccessStatus)
{
    Packet packet = with_identifiers(message_type());
    if (GetParam() != Parser::stateless) {
        add_address(packet);
    }
    add_option(packet, STATUS_CODE_OPTION_CODE, {0, 0});

    Message message = parse(packet);

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
}

TEST_P(ReplyFamilyTest, RejectsStatusWithOnlyHighByteSet)
{
    Packet packet = with_identifiers(message_type());
    if (GetParam() != Parser::stateless) {
        add_address(packet);
    }
    add_option(packet, STATUS_CODE_OPTION_CODE, {1, 0});

    Message message = parse(packet);

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_P(ReplyFamilyTest, RejectsMissingServerIdentifier)
{
    Packet packet{message_type(), 0x12, 0x34, 0x56};
    add_option(packet, CLIENT_ID_OPTION_CODE, {0, 3, 0, 1, 1, 2, 3, 4, 5, 6});
    if (GetParam() != Parser::stateless) {
        add_address(packet);
    }

    Message message = parse(packet);

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_P(ReplyFamilyTest, RejectsMissingClientIdentifier)
{
    Packet packet{message_type(), 0x12, 0x34, 0x56};
    add_option(packet, SERVER_ID_OPTION_CODE, {0, 3, 0, 1, 6, 5, 4, 3, 2, 1});
    if (GetParam() != Parser::stateless) {
        add_address(packet);
    }

    Message message = parse(packet);

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

INSTANTIATE_TEST_SUITE_P(
    MessageParsers, ReplyFamilyTest,
    testing::Values(Parser::advertisement, Parser::stateful, Parser::stateless),
    [](const testing::TestParamInfo<Parser> &info) {
        switch (info.param) {
            case Parser::advertisement: return "Advertisement";
            case Parser::stateful: return "StatefulReply";
            case Parser::stateless: return "StatelessReply";
        }
        return "UnknownParser";
    });

TEST_F(ParseMessageTest, StatefulReplyRejectsAddressT2EarlierThanT1)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet, 60, 90, 10);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, StatefulReplyAcceptsZeroAddressT2)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet, 60, 90, 0);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[2].ia_na_t.t2, 0u);
}

TEST_F(ParseMessageTest, StatefulReplyAcceptsZeroPrefixT2)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet, 60, 90, 0);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 4);
    EXPECT_EQ(message->option_list[2].ia_pd_t.t2, 0u);
}

TEST_F(ParseMessageTest, StatefulReplyRejectsInvertedPrefixLifetimes)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet, 90, 60);

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, RebindReplyAcceptsAddressWithoutMatchingRequestHint)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    request.message_type = REBIND_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_TRUE(written_lease.has_address);
}

struct ReplyMessage {
    const char *name;
    uint8_t request_type;
};

class PrefixReplyTest : public ParseMessageTest, public testing::WithParamInterface<ReplyMessage> {};

TEST_P(PrefixReplyTest, AcceptsDelegatedPrefixWithoutMatchingRequestHint)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);
    request.message_type = GetParam().request_type;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_TRUE(written_lease.has_prefix);
}

INSTANTIATE_TEST_SUITE_P(
    Dhcpv6Messages, PrefixReplyTest,
    testing::Values(ReplyMessage{"Solicit", SOLICIT_MESSAGE_TYPE},
                    ReplyMessage{"Rebind", REBIND_MESSAGE_TYPE},
                    ReplyMessage{"Release", RELEASE_MESSAGE_TYPE}),
    [](const testing::TestParamInfo<ReplyMessage> &info) { return info.param.name; });

TEST_F(ParseMessageTest, RenewReplyAcceptsMatchingAddressAtDifferentRequestOffset)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    dhcpv6_option_t request_options[4]{client_id};
    request_options[1].option_code = IA_NA_OPTION_CODE;
    request_options[2].option_code = IA_ADDR_OPTION_CODE;
    request_options[2].ia_address_t.ipv6_address = address;
    request_options[3].option_code = SERVER_ID_OPTION_CODE;
    request.option_list = request_options;
    request.option_count = 4;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_TRUE(written_lease.has_address);
}

TEST_F(ParseMessageTest, RenewReplyAcceptsMatchingPrefixAtDifferentRequestOffset)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);
    dhcpv6_option_t request_options[4]{client_id};
    request_options[1].option_code = IA_PD_OPTION_CODE;
    request_options[2].option_code = IAPREFIX_OPTION_CODE;
    request_options[2].ia_prefix_t.ipv6_prefix = prefix;
    request_options[3].option_code = SERVER_ID_OPTION_CODE;
    request.option_list = request_options;
    request.option_count = 4;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_TRUE(written_lease.has_prefix);
}

TEST_F(ParseMessageTest, RenewReplyRejectsAddressWhenRequestHasOnlyPrefix)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_address(packet);
    dhcpv6_option_t request_options[3]{client_id};
    request_options[1].option_code = IA_PD_OPTION_CODE;
    request_options[2].option_code = IAPREFIX_OPTION_CODE;
    request_options[2].ia_prefix_t.ipv6_prefix = prefix;
    request.option_list = request_options;
    request.option_count = 3;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, RenewReplyRejectsPrefixWhenRequestHasOnlyAddress)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_prefix(packet);
    dhcpv6_option_t request_options[3]{client_id};
    request_options[1].option_code = IA_NA_OPTION_CODE;
    request_options[2].option_code = IA_ADDR_OPTION_CODE;
    request_options[2].ia_address_t.ipv6_address = address;
    request.option_list = request_options;
    request.option_count = 3;
    request.message_type = RENEW_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_FALSE(message->valid);
    EXPECT_EQ(written_lease.calls, 0);
}

TEST_F(ParseMessageTest, StatefulReplyKeepsDnsOptionOnAddressListAllocationFailure)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = CONFIRM_MESSAGE_TYPE;
    fail_dns_address_allocation = true;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_FALSE(fail_dns_address_allocation);
    ASSERT_EQ(message->option_count, 3);
    ASSERT_NE(message->option_list[2].dns_recursive_name_server_t.dns_servers, nullptr);
    EXPECT_EQ(message->option_list[2].dns_recursive_name_server_t.dns_servers[15], 0x53);
}

TEST_F(ParseMessageTest, StatefulReplyConfiguresEmptyDnsListOnAllocationFailure)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = CONFIRM_MESSAGE_TYPE;
    fail_dns_address_allocation = true;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_FALSE(fail_dns_address_allocation);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands.front(), "sudo resolvectl dns test0 \n");
}

TEST_F(ParseMessageTest, StatelessReplyKeepsDnsOptionOnAddressListAllocationFailure)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
    fail_dns_address_allocation = true;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_FALSE(fail_dns_address_allocation);
    ASSERT_EQ(message->option_count, 3);
    ASSERT_NE(message->option_list[2].dns_recursive_name_server_t.dns_servers, nullptr);
    EXPECT_EQ(message->option_list[2].dns_recursive_name_server_t.dns_servers[15], 0x53);
}

TEST_F(ParseMessageTest, StatelessReplyConfiguresEmptyDnsListOnAllocationFailure)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_dns_server(packet);
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;
    fail_dns_address_allocation = true;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    EXPECT_FALSE(fail_dns_address_allocation);
    ASSERT_EQ(commands.size(), 1u);
    EXPECT_EQ(commands.front(), "sudo resolvectl dns test0 \n");
}

TEST_F(ParseMessageTest, StatefulReplyAcceptsRootOnlyDomainSearchOption)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, DOMAIN_SEARCH_LIST_OPTION_CODE, {0});
    request.message_type = CONFIRM_MESSAGE_TYPE;

    Message message(parseReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].option_length, 1);
}

TEST_F(ParseMessageTest, StatelessReplyAcceptsRootOnlyDomainSearchOption)
{
    Packet packet = with_identifiers(REPLY_MESSAGE_TYPE);
    add_option(packet, DOMAIN_SEARCH_LIST_OPTION_CODE, {0});
    request.message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

    Message message(parseStatelessReply(packet.data(), &request, interface_name, packet.size()));

    ASSERT_NE(message, nullptr);
    EXPECT_TRUE(message->valid);
    ASSERT_EQ(message->option_count, 3);
    EXPECT_EQ(message->option_list[2].option_length, 1);
}
}
