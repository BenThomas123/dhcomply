#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

extern "C" {
#include "dhcomplyDHCPv6Functions.h"
}

namespace {
using Packet = std::vector<uint8_t>;
constexpr int socket_fd = 17;
constexpr char lease_path[] = "/var/lib/dhcp/lease_test0.json";
constexpr char dad_script_path[] = "/virtual/check_dad.sh";

enum class DuidFormatFailure { none, header, address_byte };

struct Io {
    std::deque<Packet> inbox;
    Packet sent;
    sockaddr_in6 endpoint{};
    int sockfd = -1;
    std::optional<int> socket_result;
    int socket_calls = 0;
    std::deque<int> bind_errors;
    std::vector<int> bound_fds;
    std::vector<int> closed_fds;
    std::string interface;
    std::vector<useconds_t> sleeps;
    std::string config = "\n";
    bool config_missing = false;
    bool lease_exists = false;
    bool lease_write_fails = false;
    char *lease = nullptr;
    size_t lease_length = 0;
    std::string removed_path;
    bool mock_process = false;
    bool dad_readable = true;
    bool exe_path_available = true;
    std::string executable_path = "/virtual/dhcomply";
    pid_t child_pid = 42;
    bool wait_fails = false;
    bool child_signaled = false;
    bool null_device_open_fails = false;
    int child_exit_code = 0;
    int forks = 0;
    pid_t waited_for = -1;
    size_t failed_malloc_size = 0;
    int realloc_calls = 0;
    int failed_realloc_call = 0;
    bool conversion_fails = false;
    DuidFormatFailure duid_format_failure = DuidFormatFailure::none;
    bool dad_path_format_fails = false;
};

Io io;

int reject_exec(const char *path, const char *const *arguments, const char *expected_path,
                std::initializer_list<const char *> expected_arguments)
{
    if (std::strcmp(path, expected_path) != 0) {
        std::exit(126);
    }
    for (const char *argument : expected_arguments) {
        if (!*arguments || std::strcmp(*arguments, argument) != 0) {
            std::exit(126);
        }
        ++arguments;
    }
    if (*arguments) {
        std::exit(126);
    }
    errno = ENOENT;
    return -1;
}

struct FreeConfig {
    void operator()(config_t *config) const
    {
        std::free(config->oro_list);
        std::free(config->ianaIaid);
        std::free(config->iapdIaid);
        std::free(config->ia_hint.preferred_address);
        std::free(config->ia_hint.preferred_prefix);
        std::free(config->ia_hint.preferred_prefix_length);
        std::free(config);
    }
};

using Config = std::unique_ptr<config_t, FreeConfig>;
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;

Packet advertisement_with_preference(uint8_t id, uint8_t preference)
{
    return {ADVERTISE_MESSAGE_TYPE, 0, 0, id, 0, PREFERENCE_OPTION_CODE, 0, 1, preference};
}

Packet advertisement_with_address(uint8_t id, uint8_t host)
{
    Packet packet = advertisement_with_preference(id, 50);
    packet.insert(packet.end(), {
        0, IA_NA_OPTION_CODE, 0, 40,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, IA_ADDR_OPTION_CODE, 0, 24,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, host,
        0, 0, 0, 60, 0, 0, 0, 90,
    });
    return packet;
}

Packet advertisement_with_prefix(uint8_t id, uint8_t subnet)
{
    Packet packet = advertisement_with_preference(id, 50);
    packet.insert(packet.end(), {
        0, IA_PD_OPTION_CODE, 0, 41,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, IAPREFIX_OPTION_CODE, 0, 25,
        0, 0, 0, 60, 0, 0, 0, 90, 64,
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, subnet, 0, 0, 0, 0, 0, 0, 0, 0,
    });
    return packet;
}

void append_association(Packet &packet, const Packet &source)
{
    constexpr size_t first_association = 9;
    packet.insert(packet.end(), source.begin() + first_association, source.end());
}

class DHCPv6FunctionsTest : public testing::Test {
protected:
    void SetUp() override { io = {}; }
    void TearDown() override
    {
        io.socket_result.reset();
        std::free(io.lease);
        io.lease = nullptr;
    }

    std::array<uint8_t, MAX_PACKET_SIZE> buffer{};
    char interface_name[6] = "test0";
    char stateless_mode[2] = STATELESS_STRING;
    char address_mode[2] = IANA_STRING;
    char prefix_mode[2] = IAPD_STRING;
};

using DHCPv6FunctionsDeathTest = DHCPv6FunctionsTest;
}

extern "C" {
int __real_socket(int, int, int);
int __real_close(int);
int __real_access(const char *, int);
FILE *__real_fopen(const char *, const char *);
int __real_remove(const char *);
ssize_t __real_readlink(const char *, char *, size_t);
pid_t __real_fork(void);
pid_t __real_waitpid(pid_t, int *, int);
void *__real_malloc(size_t);
void *__real_realloc(void *, size_t);
const char *__real_inet_ntop(int, const void *, char *, socklen_t);
int __real_execv(const char *, char *const *);
int __real_execvp(const char *, char *const *);
[[noreturn]] void __real__exit(int);

#ifdef DHCOMPLY_ENABLE_COVERAGE
void __gcov_dump(void);
#endif

void *__wrap_malloc(size_t size)
{
    if (io.failed_malloc_size && size == io.failed_malloc_size) {
        io.failed_malloc_size = 0;
        errno = ENOMEM;
        return nullptr;
    }
    return __real_malloc(size);
}

void *__wrap_realloc(void *old, size_t size)
{
    if (io.failed_realloc_call && ++io.realloc_calls == io.failed_realloc_call) {
        errno = ENOMEM;
        return nullptr;
    }
    return __real_realloc(old, size);
}

const char *__wrap_inet_ntop(int family, const void *address, char *text, socklen_t size)
{
    if (io.conversion_fails) {
        errno = ENOSPC;
        return nullptr;
    }
    return __real_inet_ntop(family, address, text, size);
}

int __wrap_snprintf(char *destination, size_t capacity, const char *format, ...)
{
    if ((io.dad_path_format_fails && std::strcmp(format, "%s/check_dad.sh") == 0) ||
        (io.duid_format_failure == DuidFormatFailure::header &&
         std::strcmp(format, "%02X:%02X:%02X:%02X") == 0) ||
        (io.duid_format_failure == DuidFormatFailure::address_byte && std::strcmp(format, ":%02X") == 0)) {
        errno = EIO;
        return -1;
    }

    va_list arguments;
    va_start(arguments, format);
    const int result = std::vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    return result;
}

int __wrap_execl(const char *path, const char *name, ...)
{
    va_list arguments;
    va_start(arguments, name);
    const char *argv[]{name, va_arg(arguments, char *), va_arg(arguments, const char *),
                       va_arg(arguments, char *)};
    va_end(arguments);
    return reject_exec(path, argv, "/bin/bash", {"bash", dad_script_path, "test0"});
}

int __wrap_execlp(const char *path, const char *name, ...)
{
    va_list arguments;
    va_start(arguments, name);
    const char *argv[]{name, va_arg(arguments, char *), va_arg(arguments, char *),
                       va_arg(arguments, char *), va_arg(arguments, char *),
                       va_arg(arguments, char *), va_arg(arguments, char *),
                       va_arg(arguments, const char *), va_arg(arguments, char *)};
    va_end(arguments);
    return reject_exec(path, argv, "sudo", {"sudo", "ip", "-6", "addr", "del", "::1/128", "dev", "test0"});
}

// GCC coverage routes execl and execlp through their vector equivalents.
int __wrap_execv(const char *path, char *const *argv)
{
    if (!io.mock_process) {
        return __real_execv(path, argv);
    }
    return reject_exec(path, argv, "/bin/bash", {"bash", dad_script_path, "test0"});
}

int __wrap_execvp(const char *path, char *const *argv)
{
    if (!io.mock_process) {
        return __real_execvp(path, argv);
    }
    return reject_exec(path, argv, "sudo", {"sudo", "ip", "-6", "addr", "del", "::1/128", "dev", "test0"});
}

[[noreturn]] void __wrap__exit(int status)
{
#ifdef DHCOMPLY_ENABLE_COVERAGE
    if (io.mock_process) {
        __gcov_dump();
    }
#endif
    __real__exit(status);
}

int __wrap_access(const char *path, int mode)
{
    if (std::strcmp(path, lease_path) == 0 || std::strcmp(path, dad_script_path) == 0) {
        const bool accessible = std::strcmp(path, lease_path) == 0 ? io.lease_exists : io.dad_readable;
        if (accessible) {
            return 0;
        }
        errno = ENOENT;
        return -1;
    }
    return __real_access(path, mode);
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (io.null_device_open_fails && std::strcmp(path, "/dev/null") == 0) {
        errno = EIO;
        return nullptr;
    }
    if (std::strcmp(path, CONFIG_FILE_PATH) == 0) {
        if (io.config_missing) {
            errno = ENOENT;
            return nullptr;
        }
        return fmemopen(io.config.data(), io.config.size(), mode);
    }
    if (std::strcmp(path, lease_path) == 0) {
        if (io.lease_write_fails) {
            errno = EIO;
            return nullptr;
        }
        std::free(io.lease);
        io.lease = nullptr;
        io.lease_length = 0;
        return open_memstream(&io.lease, &io.lease_length);
    }
    return __real_fopen(path, mode);
}

int __wrap_remove(const char *path)
{
    if (std::strcmp(path, lease_path) == 0) {
        io.removed_path = path;
        return 0;
    }
    return __real_remove(path);
}

int __wrap_socket(int family, int type, int protocol)
{
    if (!io.socket_result.has_value()) {
        return __real_socket(family, type, protocol);
    }
    EXPECT_EQ(family, AF_INET6);
    EXPECT_EQ(type, SOCK_DGRAM);
    EXPECT_EQ(protocol, IPPROTO_UDP);
    ++io.socket_calls;
    if (*io.socket_result < 0) {
        errno = EMFILE;
    }
    return *io.socket_result;
}

int __wrap_close(int fd)
{
    if (!io.socket_result.has_value()) {
        return __real_close(fd);
    }
    io.closed_fds.push_back(fd);
    return 0;
}

int __wrap_bind(int fd, const sockaddr *address, socklen_t length)
{
    io.sockfd = fd;
    io.bound_fds.push_back(fd);
    if (length == sizeof(io.endpoint)) {
        std::memcpy(&io.endpoint, address, length);
    }
    if (io.bind_errors.empty()) {
        return 0;
    }
    const int error = io.bind_errors.front();
    io.bind_errors.pop_front();
    errno = error;
    return -1;
}

ssize_t __wrap_sendto(int fd, const void *buffer, size_t length, int flags,
                      const sockaddr *address, socklen_t address_length)
{
    EXPECT_EQ(flags, 0);
    io.sockfd = fd;
    if (address_length == sizeof(io.endpoint)) {
        std::memcpy(&io.endpoint, address, address_length);
    }
    const auto *bytes = static_cast<const uint8_t *>(buffer);
    io.sent.assign(bytes, bytes + length);
    return length;
}

unsigned int __wrap_if_nametoindex(const char *name)
{
    io.interface = name;
    return 42;
}

int __wrap_select(int, fd_set *, fd_set *, fd_set *, timeval *)
{
    return io.inbox.empty() ? 0 : 1;
}

ssize_t __wrap_recv(int, void *destination, size_t capacity, int)
{
    if (io.inbox.empty()) {
        errno = EAGAIN;
        return -1;
    }
    const auto &packet = io.inbox.front();
    const size_t bytes = std::min(packet.size(), capacity);
    if (bytes) {
        std::memcpy(destination, packet.data(), bytes);
    }
    io.inbox.pop_front();
    return bytes;
}

ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int)
{
    std::memset(buffer, 0x5a, length);
    return length;
}

int __wrap_usleep(useconds_t delay)
{
    io.sleeps.push_back(delay);
    return 0;
}

ssize_t __wrap_readlink(const char *path, char *buffer, size_t capacity)
{
    if (io.mock_process && std::strcmp(path, "/proc/self/exe") == 0) {
        if (!io.exe_path_available) {
            errno = ENOENT;
            return -1;
        }
        const size_t count = std::min(capacity, io.executable_path.size());
        std::memcpy(buffer, io.executable_path.data(), count);
        return count;
    }
    return __real_readlink(path, buffer, capacity);
}

pid_t __wrap_fork(void)
{
    if (io.mock_process) {
        ++io.forks;
        if (io.child_pid < 0) {
            errno = EAGAIN;
        }
        return io.child_pid;
    }
    return __real_fork();
}

pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    if (io.mock_process) {
        io.waited_for = pid;
        if (io.wait_fails) {
            errno = ECHILD;
            return -1;
        }
        if (status) {
            *status = io.child_signaled ? SIGTERM : io.child_exit_code << 8;
        }
        return pid;
    }
    return __real_waitpid(pid, status, options);
}
}

namespace {
TEST_F(DHCPv6FunctionsTest, StatelessModeDisablesIdentityAssociations)
{
    Config config(read_config_file(stateless_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_FALSE(config->na);
    EXPECT_FALSE(config->pd);
}

TEST_F(DHCPv6FunctionsTest, ConfigSetsStatelessDefaultOption)
{
    Config config(read_config_file(stateless_mode));
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(config->oro_list_length, 1u);
    EXPECT_EQ(config->oro_list[0], INF_MAX_RT_OPTION_CODE);
}

TEST_F(DHCPv6FunctionsTest, AddressModeSelectsOnlyAddressAssociation)
{
    Config config(read_config_file(address_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_TRUE(config->na);
    EXPECT_FALSE(config->pd);
}

TEST_F(DHCPv6FunctionsTest, ConfigIgnoresCommentedRapidCommit)
{
    io.config = "  " COMMENT_CONFIG_FILE_LINE " " RAPID_COMMIT_LINE "\n";
    Config config(read_config_file(address_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_FALSE(config->rapid_commit);
}

TEST_F(DHCPv6FunctionsTest, ConfigDefaultsT2FromT1)
{
    io.config = T1_CONFIG_FILE_LINE "10\n";
    Config config(read_config_file(address_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_EQ(config->t2, 5010u);
}

TEST_F(DHCPv6FunctionsTest, PrefixModeSelectsOnlyPrefixAssociation)
{
    Config config(read_config_file(prefix_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_FALSE(config->na);
    EXPECT_TRUE(config->pd);
}

TEST_F(DHCPv6FunctionsTest, ConfigEnablesRapidCommit)
{
    io.config = RAPID_COMMIT_LINE "\n";
    Config config(read_config_file(prefix_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_TRUE(config->rapid_commit);
}

TEST_F(DHCPv6FunctionsTest, ConfigReadsPreferredPrefixWithExplicitLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56\n"
                PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n";
    Config config(read_config_file(prefix_mode));
    ASSERT_NE(config, nullptr);
    ASSERT_NE(config->ia_hint.preferred_prefix_length, nullptr);
    EXPECT_EQ(*config->ia_hint.preferred_prefix_length, 56u);
    ASSERT_NE(config->ia_hint.preferred_prefix, nullptr);
    EXPECT_EQ(*config->ia_hint.preferred_prefix, static_cast<uint128_t>(0x20010db8u) << 96);
}

TEST_F(DHCPv6FunctionsTest, CombinedModeSelectsBothAssociations)
{
    char mode[] = IA_BOTH_STRING;
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    EXPECT_TRUE(config->na);
    EXPECT_TRUE(config->pd);
}

TEST_F(DHCPv6FunctionsTest, ConfigReadsExplicitLeaseTimers)
{
    char mode[] = IA_BOTH_STRING;
    io.config = T1_CONFIG_FILE_LINE "10\n"
                T2_CONFIG_FILE_LINE "20\n";
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    EXPECT_EQ(config->t1, 10u);
    EXPECT_EQ(config->t2, 20u);
}

TEST_F(DHCPv6FunctionsTest, ConfigReadsAddressIaid)
{
    char mode[] = IA_BOTH_STRING;
    io.config = "IANA IAID: 12AB\n";
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    EXPECT_STREQ(config->ianaIaid, "12AB");
}

TEST_F(DHCPv6FunctionsTest, ConfigReadsPrefixIaid)
{
    char mode[] = IA_BOTH_STRING;
    io.config = "IAPD IAID: 34CD\n";
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    EXPECT_STREQ(config->iapdIaid, "34CD");
}

TEST_F(DHCPv6FunctionsTest, ConfigReadsIndentedAddressHint)
{
    char mode[] = IA_BOTH_STRING;
    io.config = "  " PREFERRED_ADDRESS_CONFIG_FILE_LINE "2001:db8::3\n";
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    ASSERT_NE(config->ia_hint.preferred_address, nullptr);
    EXPECT_EQ(*config->ia_hint.preferred_address, (static_cast<uint128_t>(0x20010db8u) << 96) | 3u);
}

TEST_F(DHCPv6FunctionsTest, ConfigDefaultsPreferredPrefixLength)
{
    char mode[] = IA_BOTH_STRING;
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n";
    Config config(read_config_file(mode));
    ASSERT_NE(config, nullptr);
    ASSERT_NE(config->ia_hint.preferred_prefix_length, nullptr);
    EXPECT_EQ(*config->ia_hint.preferred_prefix_length, 64u);
}

TEST_F(DHCPv6FunctionsTest, StatelessConfigOrdersRequestedOptionsAroundDefaultTimer)
{
    io.config = "dns-servers\nsol-max-rt\n";
    Config config(read_config_file(stateless_mode));
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(config->oro_list_length, 3);
    EXPECT_EQ(config->oro_list[0], DNS_SERVERS_OPTION_CODE);
    EXPECT_EQ(config->oro_list[1], INF_MAX_RT_OPTION_CODE);
    EXPECT_EQ(config->oro_list[2], SOL_MAX_RT_OPTION_CODE);
}

TEST_F(DHCPv6FunctionsTest, StatefulConfigIncludesExplicitInformationMaxTimer)
{
    io.config = "inf-max-rt\n";
    Config config(read_config_file(address_mode));
    ASSERT_NE(config, nullptr);
    ASSERT_EQ(config->oro_list_length, 2);
    EXPECT_EQ(config->oro_list[0], SOL_MAX_RT_OPTION_CODE);
    EXPECT_EQ(config->oro_list[1], INF_MAX_RT_OPTION_CODE);
}

TEST_F(DHCPv6FunctionsTest, StatelessConfigIgnoresAddressHint)
{
    io.config = PREFERRED_ADDRESS_CONFIG_FILE_LINE "2001:db8::1\n";
    Config stateless(read_config_file(stateless_mode));
    ASSERT_NE(stateless, nullptr);
    EXPECT_EQ(stateless->ia_hint.preferred_address, nullptr);
}

TEST_F(DHCPv6FunctionsTest, StatelessConfigIgnoresPrefixLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56\n";
    Config stateless(read_config_file(stateless_mode));
    ASSERT_NE(stateless, nullptr);
    EXPECT_EQ(stateless->ia_hint.preferred_prefix_length, nullptr);
}

TEST_F(DHCPv6FunctionsTest, StatelessConfigIgnoresPrefixHint)
{
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n";
    Config stateless(read_config_file(stateless_mode));
    ASSERT_NE(stateless, nullptr);
    EXPECT_EQ(stateless->ia_hint.preferred_prefix, nullptr);
}

TEST_F(DHCPv6FunctionsTest, ConfigIgnoresUnrecognizedPrefixDirective)
{
    io.config = "send dhcp6.preferred-prefix-not-a-directive\n";
    Config config(read_config_file(prefix_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_EQ(config->ia_hint.preferred_prefix, nullptr);
}

struct ReconfigureOption {
    const char *line;
    uint8_t code;
    const char *name;
};

class ReconfigureConfigTest : public DHCPv6FunctionsTest,
                              public testing::WithParamInterface<ReconfigureOption> {};

TEST_P(ReconfigureConfigTest, DecodesMessageType)
{
    io.config = std::string(GetParam().line) + "\n";
    Config config(read_config_file(address_mode));
    ASSERT_NE(config, nullptr);
    EXPECT_EQ(config->reconfigure, GetParam().code);
}

INSTANTIATE_TEST_SUITE_P(MessageTypes, ReconfigureConfigTest,
                         testing::Values(ReconfigureOption{RECONFIGURE_CONFIG_FILE_LINE_RENEW, 5, "Renew"},
                                         ReconfigureOption{RECONFIGURE_CONFIG_FILE_LINE_REBIND, 6, "Rebind"},
                                         ReconfigureOption{RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, 7, "InformationRequest"}),
                         [](const testing::TestParamInfo<ReconfigureOption> &info) {
                             return info.param.name;
                         });

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsDuplicatePreferredAddress)
{
    io.config = PREFERRED_ADDRESS_CONFIG_FILE_LINE "2001:db8::1\n"
                PREFERRED_ADDRESS_CONFIG_FILE_LINE "2001:db8::2\n";
    EXPECT_EXIT(read_config_file(address_mode), testing::ExitedWithCode(255),
                "Invalid or duplicate preferred address");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsInvalidPreferredAddress)
{
    io.config = PREFERRED_ADDRESS_CONFIG_FILE_LINE "invalid\n";
    EXPECT_EXIT(read_config_file(address_mode), testing::ExitedWithCode(255),
                "Invalid preferred IPv6 address");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsDuplicatePreferredPrefix)
{
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n"
                PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8:1::\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid or duplicate preferred prefix");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsInvalidPreferredPrefix)
{
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "invalid\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid preferred IPv6 prefix");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsExcessivePrefixLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "129\n"
                PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsDuplicatePrefixLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56\n"
                PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "64\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsPrefixLengthAfterPrefix)
{
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "2001:db8::\n"
                PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsPrefixLengthWithTrailingText)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56bits\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsIntegerOverflowInPrefixLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "18446744073709551616\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsEmptyAddressHint)
{
    io.config = PREFERRED_ADDRESS_CONFIG_FILE_LINE "\n";
    EXPECT_EXIT(read_config_file(address_mode), testing::ExitedWithCode(255),
                "Invalid or duplicate preferred address");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsEmptyPrefixHint)
{
    io.config = PREFERRED_PREFIX_CONFIG_FILE_LINE "\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid or duplicate preferred prefix");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsEmptyPrefixLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "Invalid, duplicate, or misplaced preferred prefix length");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsT2WithoutT1)
{
    io.config = T2_CONFIG_FILE_LINE "20\n";
    EXPECT_EXIT(read_config_file(address_mode), testing::ExitedWithCode(255),
                "You cannot configure T2 without configuring T1");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsT2BeforeT1)
{
    io.config = T1_CONFIG_FILE_LINE "20\n"
                T2_CONFIG_FILE_LINE "10\n";
    EXPECT_EXIT(read_config_file(address_mode), testing::ExitedWithCode(255),
                "You must configure T2 to be greater than T1");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRequiresPrefixForLength)
{
    io.config = PREFERRED_PREFIX_LENGTH_CONFIG_FILE_LINE "56\n";
    EXPECT_EXIT(read_config_file(prefix_mode), testing::ExitedWithCode(255),
                "A preferred prefix length requires a preferred prefix");
}

TEST_F(DHCPv6FunctionsDeathTest, ConfigRejectsMissingFile)
{
    io.config_missing = true;
    EXPECT_EXIT(read_config_file(stateless_mode), testing::ExitedWithCode(255), "Invalid file pointer");
}

TEST_F(DHCPv6FunctionsTest, GetIaidDecodesConfiguredHexadecimal)
{
    char configured[] = "AB0123";
    EXPECT_EQ(getIAID(configured), 0xAB0123u);
}

TEST_F(DHCPv6FunctionsTest, GetIaidUsesRandomBytesWhenUnset)
{
    EXPECT_EQ(getIAID(nullptr), 0x5a5a5a5au);
}

TEST_F(DHCPv6FunctionsTest, BindPropagatesBindError)
{
    io.bind_errors = {EACCES};
    EXPECT_EQ(bind_dhcpv6_client_socket(socket_fd), -1);
}

TEST_F(DHCPv6FunctionsTest, BindUsesSuppliedSocket)
{
    bind_dhcpv6_client_socket(socket_fd);
    EXPECT_EQ(io.sockfd, socket_fd);
}

TEST_F(DHCPv6FunctionsTest, BindUsesWildcardClientEndpoint)
{
    bind_dhcpv6_client_socket(socket_fd);
    EXPECT_EQ(io.endpoint.sin6_family, AF_INET6);
    EXPECT_EQ(ntohs(io.endpoint.sin6_port), DHCP_CLIENT_PORT);
    EXPECT_TRUE(IN6_IS_ADDR_UNSPECIFIED(&io.endpoint.sin6_addr));
}

TEST_F(DHCPv6FunctionsTest, HandoffStopsWhenSocketCreationFails)
{
    io.socket_result = -1;
    EXPECT_EQ(open_lease_handoff_socket(), -1);
    EXPECT_EQ(io.socket_calls, 1);
    EXPECT_TRUE(io.bound_fds.empty());
    EXPECT_TRUE(io.sleeps.empty());
    EXPECT_TRUE(io.closed_fds.empty());
}

TEST_F(DHCPv6FunctionsTest, HandoffReturnsBoundDescriptorZero)
{
    io.socket_result = 0;
    EXPECT_EQ(open_lease_handoff_socket(), 0);
    EXPECT_EQ(io.socket_calls, 1);
    EXPECT_EQ(io.bound_fds, std::vector<int>{0});
    EXPECT_TRUE(io.sleeps.empty());
    EXPECT_TRUE(io.closed_fds.empty());
}

TEST_F(DHCPv6FunctionsTest, HandoffRetriesOnTheSameSocketUntilPortIsAvailable)
{
    io.socket_result = socket_fd;
    io.bind_errors = {EADDRINUSE, EADDRINUSE};
    EXPECT_EQ(open_lease_handoff_socket(), socket_fd);
    EXPECT_EQ(io.socket_calls, 1);
    EXPECT_EQ(io.bound_fds, (std::vector<int>{socket_fd, socket_fd, socket_fd}));
    EXPECT_EQ(io.sleeps, (std::vector<useconds_t>{100000, 100000}));
    EXPECT_TRUE(io.closed_fds.empty());
}

TEST_F(DHCPv6FunctionsTest, HandoffClosesSocketOnPermanentBindError)
{
    io.socket_result = socket_fd;
    io.bind_errors = {EACCES};
    EXPECT_EQ(open_lease_handoff_socket(), -1);
    EXPECT_EQ(io.bound_fds, std::vector<int>{socket_fd});
    EXPECT_EQ(io.closed_fds, std::vector<int>{socket_fd});
    EXPECT_TRUE(io.sleeps.empty());
}

TEST_F(DHCPv6FunctionsTest, HandoffStopsRetryingWhenBindErrorChanges)
{
    io.socket_result = socket_fd;
    io.bind_errors = {EADDRINUSE, EACCES};
    EXPECT_EQ(open_lease_handoff_socket(), -1);
    EXPECT_EQ(io.bound_fds, (std::vector<int>{socket_fd, socket_fd}));
    EXPECT_EQ(io.sleeps, std::vector<useconds_t>{100000});
    EXPECT_EQ(io.closed_fds, std::vector<int>{socket_fd});
}

TEST_F(DHCPv6FunctionsTest, MulticastSendUsesSuppliedSocket)
{
    Packet request{SOLICIT_MESSAGE_TYPE, 1, 2, 3};
    send_dhcpv6_multicast_packet(socket_fd, request.data(), request.size(), interface_name);
    EXPECT_EQ(io.sockfd, socket_fd);
}

TEST_F(DHCPv6FunctionsTest, MulticastSendForwardsPayload)
{
    Packet request{SOLICIT_MESSAGE_TYPE, 1, 2, 3};
    send_dhcpv6_multicast_packet(socket_fd, request.data(), request.size(), interface_name);
    EXPECT_EQ(io.sent, request);
}

TEST_F(DHCPv6FunctionsTest, MulticastSendTargetsDhcpServerGroup)
{
    Packet request{SOLICIT_MESSAGE_TYPE, 1, 2, 3};
    send_dhcpv6_multicast_packet(socket_fd, request.data(), request.size(), interface_name);
    EXPECT_EQ(io.endpoint.sin6_family, AF_INET6);
    EXPECT_EQ(ntohs(io.endpoint.sin6_port), DHCP_SERVER_PORT);
    in6_addr multicast{};
    ASSERT_EQ(inet_pton(AF_INET6, "ff02::1:2", &multicast), 1);
    EXPECT_TRUE(IN6_ARE_ADDR_EQUAL(&io.endpoint.sin6_addr, &multicast));
}

TEST_F(DHCPv6FunctionsTest, MulticastSendUsesInterfaceScope)
{
    Packet request{SOLICIT_MESSAGE_TYPE, 1, 2, 3};
    send_dhcpv6_multicast_packet(socket_fd, request.data(), request.size(), interface_name);
    EXPECT_EQ(io.endpoint.sin6_scope_id, 42u);
    EXPECT_EQ(io.interface, interface_name);
}

TEST_F(DHCPv6FunctionsTest, CheckForReplyCopiesBytes)
{
    io.inbox.push_back({REPLY_MESSAGE_TYPE, 1, 2, 3});
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), REPLY_MESSAGE_TYPE), 4);
    EXPECT_EQ(buffer[0], REPLY_MESSAGE_TYPE);
    EXPECT_EQ(buffer[3], 3u);
}

TEST_F(DHCPv6FunctionsTest, CheckForReplyIgnoresOtherMessageTypes)
{
    io.inbox.push_back({ADVERTISE_MESSAGE_TYPE, 1, 2, 3});
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), REPLY_MESSAGE_TYPE), 0);
}

TEST_F(DHCPv6FunctionsTest, CheckForReplyReportsEmptyDatagram)
{
    io.inbox.emplace_back();
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), REPLY_MESSAGE_TYPE), 0);
}

TEST_F(DHCPv6FunctionsTest, CheckForReplyReportsTimeout)
{
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), REPLY_MESSAGE_TYPE), 0);
}

TEST_F(DHCPv6FunctionsTest, CheckForMessageReportsUnsupportedType)
{
    io.inbox.push_back({REPLY_MESSAGE_TYPE, 1, 2, 3});
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), SOLICIT_MESSAGE_TYPE), 0);
    EXPECT_EQ(io.inbox.size(), 1u);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSelectsHighestPreference)
{
    io.inbox.push_back({REPLY_MESSAGE_TYPE, 1, 2, 3});
    io.inbox.push_back(advertisement_with_preference(1, 10));
    io.inbox.push_back(advertisement_with_preference(2, 20));
    EXPECT_EQ(check_for_message(socket_fd, buffer.data(), ADVERTISE_MESSAGE_TYPE), 9);
    EXPECT_EQ(buffer[3], 2u);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementStopsAtMaximumPreference)
{
    io.inbox.push_back(advertisement_with_preference(1, 255));
    io.inbox.push_back(advertisement_with_preference(2, 10));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 1u);
    EXPECT_EQ(io.inbox.size(), 1u);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementBreaksPreferenceTieByAddressHint)
{
    io.inbox.push_back(advertisement_with_address(1, 50));
    io.inbox.push_back(advertisement_with_address(2, 24));
    uint128_t hint = (static_cast<uint128_t>(0x20010db8u) << 96) | 25u;
    config_t config{};
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementReportsNoCandidates)
{
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 0);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementBreaksPreferenceTieByPrefixHint)
{
    io.inbox.push_back(advertisement_with_prefix(1, 50));
    io.inbox.push_back(advertisement_with_prefix(2, 24));
    uint128_t hint = (static_cast<uint128_t>(0x20010db8u) << 96) | (static_cast<uint128_t>(25) << 64);
    config_t config{};
    config.pd = true;
    config.ia_hint.preferred_prefix = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementPrefersCandidateWithAddressHint)
{
    io.inbox.push_back(advertisement_with_preference(1, 50));
    io.inbox.push_back(advertisement_with_address(2, 24));
    uint128_t hint = 1;
    config_t config{};
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementPrefersCandidateWithPrefixHint)
{
    io.inbox.push_back(advertisement_with_preference(1, 50));
    io.inbox.push_back(advertisement_with_prefix(2, 24));
    uint128_t hint = 1;
    config_t config{};
    config.pd = true;
    config.ia_hint.preferred_prefix = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementTreatsMissingPreferenceAsZero)
{
    const Packet no_preference{ADVERTISE_MESSAGE_TYPE, 0, 0, 1, 0, ELAPSED_TIME_OPTION_CODE, 0, 2, 0, 5};
    io.inbox.push_back(no_preference);
    io.inbox.push_back(advertisement_with_preference(2, 1));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 2);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementIgnoresNonSingleBytePreference)
{
    io.inbox.push_back({ADVERTISE_MESSAGE_TYPE, 0, 0, 1, 0, PREFERENCE_OPTION_CODE, 0, 2, 255, 0});
    io.inbox.push_back(advertisement_with_preference(2, 1));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 2);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementIgnoresEmptyDatagram)
{
    io.inbox.emplace_back();
    io.inbox.push_back(advertisement_with_preference(2, 1));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 2);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementKeepsEarlierEqualPreference)
{
    io.inbox.push_back(advertisement_with_preference(1, 100));
    io.inbox.push_back(advertisement_with_preference(2, 1));
    io.inbox.push_back(advertisement_with_preference(3, 100));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 1);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementAllowsEnabledAssociationsWithoutHints)
{
    config_t config{};
    config.na = true;
    config.pd = true;
    io.inbox.push_back(advertisement_with_preference(4, 100));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), 9);
    EXPECT_EQ(buffer[3], 4);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSkipsUndersizedAddressAssociation)
{
    auto short_association = advertisement_with_preference(1, 50);
    short_association.insert(short_association.end(), {0, IA_NA_OPTION_CODE, 0, 2, 0, 0});
    config_t config{};
    uint128_t hint = 1;
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    io.inbox.push_back(short_association);
    const auto expected = advertisement_with_address(3, 24);
    io.inbox.push_back(expected);
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_EQ(buffer[3], 3);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSkipsUndersizedAddressSuboption)
{
    auto short_address = advertisement_with_preference(2, 50);
    short_address.insert(short_address.end(), {
        0, IA_NA_OPTION_CODE, 0, 20,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        0, IA_ADDR_OPTION_CODE, 0, 4, 1, 2, 3, 4,
    });
    config_t config{};
    uint128_t hint = 1;
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    io.inbox.push_back(short_address);
    const auto expected = advertisement_with_address(3, 24);
    io.inbox.push_back(expected);
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_EQ(buffer[3], 3);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementUsesClosestOfMultipleAddresses)
{
    constexpr size_t association_length_byte = 12;
    constexpr size_t nested_address_offset = 25;
    auto multiple = advertisement_with_address(2, 49);
    const auto closer = advertisement_with_address(2, 25);
    const auto farther = advertisement_with_address(2, 52);
    multiple.insert(multiple.end(), {0, STATUS_CODE_OPTION_CODE, 0, 2, 0, 0});
    multiple.insert(multiple.end(), closer.begin() + nested_address_offset, closer.end());
    multiple.insert(multiple.end(), farther.begin() + nested_address_offset, farther.end());
    multiple[association_length_byte] = static_cast<uint8_t>(multiple.size() - 13);
    config_t config{};
    uint128_t hint = (static_cast<uint128_t>(0x20010db8u) << 96) | 24u;
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    io.inbox.push_back(advertisement_with_address(1, 21));
    io.inbox.push_back(multiple);
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), multiple.size());
    EXPECT_EQ(buffer[3], 2);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSaturatesCombinedHintDistance)
{
    constexpr size_t prefix_bytes = 38;
    auto exact_prefix = advertisement_with_prefix(1, 0);
    std::fill(exact_prefix.begin() + prefix_bytes, exact_prefix.end(), 0);
    exact_prefix[prefix_bytes] = 0xfd;
    auto moderate_distance = advertisement_with_address(1, 24);
    append_association(moderate_distance, exact_prefix);
    auto excessive_distance = advertisement_with_address(2, 24);
    append_association(excessive_distance, advertisement_with_prefix(2, 0));
    config_t config{};
    uint128_t hint = static_cast<uint128_t>(0xfd) << 120;
    config.na = true;
    config.pd = true;
    config.ia_hint.preferred_address = &hint;
    config.ia_hint.preferred_prefix = &hint;
    io.inbox.push_back(moderate_distance);
    io.inbox.push_back(excessive_distance);
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), moderate_distance.size());
    EXPECT_EQ(buffer[3], 1);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementIgnoresTruncatedPreferenceValue)
{
    const Packet truncated{ADVERTISE_MESSAGE_TYPE, 0, 0, 1, 0, PREFERENCE_OPTION_CODE, 0, 1};
    io.inbox.push_back(truncated);
    io.inbox.push_back(advertisement_with_preference(2, 1));
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 9);
    EXPECT_EQ(buffer[3], 2);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSkipsTruncatedNestedAddress)
{
    auto truncated = advertisement_with_address(1, 24);
    constexpr size_t address_length_low_byte = 28;
    truncated[address_length_low_byte] = 25;
    io.inbox.push_back(truncated);
    io.inbox.push_back(advertisement_with_address(2, 24));
    uint128_t hint = 1;
    config_t config{};
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementSkipsTruncatedAddressAssociation)
{
    auto truncated = advertisement_with_address(1, 24);
    truncated.pop_back();
    io.inbox.push_back(truncated);
    io.inbox.push_back(advertisement_with_address(2, 24));
    uint128_t hint = 1;
    config_t config{};
    config.na = true;
    config.ia_hint.preferred_address = &hint;
    const auto expected = io.inbox.back();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), &config), expected.size());
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), buffer.begin()));
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementHandlesPacketAllocationFailure)
{
    const auto packet = advertisement_with_preference(1, 100);
    io.inbox.push_back(packet);
    io.failed_malloc_size = packet.size();
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 0);
    EXPECT_EQ(io.failed_malloc_size, 0u);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementHandlesListAllocationFailure)
{
    io.inbox.push_back(advertisement_with_preference(1, 100));
    io.failed_realloc_call = 1;
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 0);
}

TEST_F(DHCPv6FunctionsTest, CheckForAdvertisementHandlesLengthAllocationFailure)
{
    io.inbox.push_back(advertisement_with_preference(1, 100));
    io.failed_realloc_call = 2;
    EXPECT_EQ(check_for_advertisement(socket_fd, buffer.data(), nullptr), 0);
}

TEST_F(DHCPv6FunctionsTest, RapidCommitReportsReplyType)
{
    io.inbox.push_back({REPLY_MESSAGE_TYPE, 1, 2, 3});
    int type = 0;
    EXPECT_EQ(check_for_rapid_commit_message(socket_fd, buffer.data(), &type), 4);
    EXPECT_EQ(type, REPLY_MESSAGE_TYPE);
}

TEST_F(DHCPv6FunctionsTest, RapidCommitReportsAdvertisementType)
{
    io.inbox.push_back({ADVERTISE_MESSAGE_TYPE, 1, 2, 3});
    int type = 0;
    EXPECT_EQ(check_for_rapid_commit_message(socket_fd, buffer.data(), &type), 4);
    EXPECT_EQ(type, ADVERTISE_MESSAGE_TYPE);
}

TEST_F(DHCPv6FunctionsTest, RapidCommitIgnoresUnexpectedType)
{
    io.inbox.push_back({SOLICIT_MESSAGE_TYPE, 1, 2, 3});
    int type = 99;
    EXPECT_EQ(check_for_rapid_commit_message(socket_fd, buffer.data(), &type), 0);
    EXPECT_EQ(type, 99);
}

TEST_F(DHCPv6FunctionsTest, RapidCommitReportsReceiveTimeout)
{
    int type = 99;
    EXPECT_EQ(check_for_rapid_commit_message(socket_fd, buffer.data(), &type), 0);
    EXPECT_EQ(type, 99);
}

TEST_F(DHCPv6FunctionsTest, RapidCommitReportsEmptyDatagram)
{
    io.inbox.emplace_back();
    int type = 99;
    EXPECT_EQ(check_for_rapid_commit_message(socket_fd, buffer.data(), &type), 0);
    EXPECT_EQ(type, 99);
}

TEST_F(DHCPv6FunctionsTest, DadFailureRecognizesDuplicateAddressExitCode)
{
    io.mock_process = true;
    io.child_exit_code = 2;
    EXPECT_TRUE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 1);
    EXPECT_EQ(io.waited_for, 42);
}

TEST_F(DHCPv6FunctionsTest, DadFailureReportsNormalExitAsSuccess)
{
    io.mock_process = true;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 1);
}

TEST_F(DHCPv6FunctionsTest, DadFailureSkipsUnreadableScript)
{
    io.mock_process = true;
    io.dad_readable = false;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesMissingExecutablePath)
{
    io.mock_process = true;
    io.exe_path_available = false;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesExecutablePathWithNoDirectory)
{
    io.mock_process = true;
    io.executable_path = "dhcomply";
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesScriptPathThatWouldBeTooLong)
{
    io.mock_process = true;
    io.executable_path = "/" + std::string(PATH_MAX - 4, 'd') + "/x";
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesScriptPathFormattingError)
{
    io.mock_process = true;
    io.dad_path_format_fails = true;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, DadFailureDoesNotReportTerminatedChildAsDuplicate)
{
    io.mock_process = true;
    io.child_signaled = true;
    EXPECT_FALSE(check_dad_failure(interface_name));
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesForkError)
{
    io.mock_process = true;
    io.child_pid = -1;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.forks, 1);
    EXPECT_EQ(io.waited_for, -1);
}

TEST_F(DHCPv6FunctionsTest, DadFailureHandlesWaitError)
{
    io.mock_process = true;
    io.wait_fails = true;
    EXPECT_FALSE(check_dad_failure(interface_name));
    EXPECT_EQ(io.waited_for, 42);
}

TEST_F(DHCPv6FunctionsTest, DadFailureDoesNotReportOtherScriptExitCodesAsDuplicates)
{
    io.mock_process = true;
    io.child_exit_code = 1;
    EXPECT_FALSE(check_dad_failure(interface_name));
}

TEST_F(DHCPv6FunctionsDeathTest, DadChildExitsWhenScriptCannotExecute)
{
    EXPECT_EXIT({
        io.mock_process = true;
        io.child_pid = 0;
        check_dad_failure(interface_name);
    }, testing::ExitedWithCode(127), "Unable to execute DAD check script");
}

TEST_F(DHCPv6FunctionsTest, TransactionIdDecodesThreeBytes)
{
    EXPECT_EQ(valid_transaction_id(0xa1, 0xb2, 0xc3), 0xa1b2c3u);
}

TEST_F(DHCPv6FunctionsTest, OptionCountIncludesFlattenedIdentityAssociation)
{
    auto packet = advertisement_with_address(1, 24);
    uint8_t associations = 0;
    EXPECT_EQ(get_option_count(packet.data(), packet.size(), &associations), 3);
    EXPECT_EQ(associations, 1);
}

TEST_F(DHCPv6FunctionsTest, OptionCountIncludesFlattenedDelegatedPrefix)
{
    auto packet = advertisement_with_prefix(1, 24);
    packet.insert(packet.end(), {0, RAPID_COMMIT_OPTION_CODE, 0, 0});
    uint8_t associations = 0;
    EXPECT_EQ(get_option_count(packet.data(), packet.size(), &associations), 4);
    EXPECT_EQ(associations, 1);
}

TEST_F(DHCPv6FunctionsTest, OptionIndexAccountsForFlattenedDelegatedPrefix)
{
    auto packet = advertisement_with_prefix(1, 24);
    packet.insert(packet.end(), {0, RAPID_COMMIT_OPTION_CODE, 0, 0});
    EXPECT_EQ(get_option_index(packet.data(), packet.size(), RAPID_COMMIT_OPTION_CODE), 3);
}

TEST_F(DHCPv6FunctionsTest, OptionIndexAccountsForFlattenedIdentityAssociation)
{
    auto packet = advertisement_with_address(1, 24);
    packet.insert(packet.end(), {0, RAPID_COMMIT_OPTION_CODE, 0, 0});
    EXPECT_EQ(get_option_index(packet.data(), packet.size(), RAPID_COMMIT_OPTION_CODE), 3);
}

TEST_F(DHCPv6FunctionsTest, OptionIndexReportsAbsentOptionAfterAddressAssociation)
{
    auto packet = advertisement_with_address(1, 24);
    packet.insert(packet.end(), {0, RAPID_COMMIT_OPTION_CODE, 0, 0});
    EXPECT_EQ(get_option_index(packet.data(), packet.size(), SERVER_ID_OPTION_CODE), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseSerializesServerIdentifier)
{
    uint8_t mac[] = {0x00, 0x12, 0x34, 0xab, 0xcd, 0xef};
    duid_ll_t duid{3, 1, mac};
    char address[] = "2001:db8::1";
    IANA_t iana{0x1234, 20, 30, address, 90, 60};

    ASSERT_EQ(writeLease(&iana, nullptr, interface_name, &duid, sizeof(mac)), 0);
    ASSERT_NE(io.lease, nullptr);
    Json document(cJSON_Parse(io.lease), cJSON_Delete);
    ASSERT_NE(document, nullptr);

    cJSON *server = cJSON_GetObjectItemCaseSensitive(document.get(), "server_duid");
    ASSERT_TRUE(cJSON_IsObject(server));
    EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(server, "duid")),
                 "00:03:00:01:00:12:34:AB:CD:EF");
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseSerializesAddressLease)
{
    uint8_t mac[] = {0x00, 0x12, 0x34, 0xab, 0xcd, 0xef};
    duid_ll_t duid{3, 1, mac};
    char address[] = "2001:db8::1";
    IANA_t iana{0x1234, 20, 30, address, 90, 60};

    ASSERT_EQ(writeLease(&iana, nullptr, interface_name, &duid, sizeof(mac)), 0);
    ASSERT_NE(io.lease, nullptr);
    Json document(cJSON_Parse(io.lease), cJSON_Delete);
    ASSERT_NE(document, nullptr);

    cJSON *leases = cJSON_GetObjectItemCaseSensitive(document.get(), "leases");
    ASSERT_EQ(cJSON_GetArraySize(leases), 1);
    cJSON *lease = cJSON_GetArrayItem(leases, 0);
    EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(lease, "iaid")), "00001234");
    EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(lease, "address")), address);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseSerializesDelegatedPrefix)
{
    uint8_t mac[] = {1, 2, 3, 4, 5, 6};
    duid_ll_t duid{3, 1, mac};
    IAPD_t iapd{};
    iapd.prefix = static_cast<uint128_t>(0x20010db8u) << 96;
    iapd.prefix_length = 56;
    io.lease_exists = true;

    ASSERT_EQ(writeLease(nullptr, &iapd, interface_name, &duid, sizeof(mac)), 0);
    ASSERT_NE(io.lease, nullptr);
    Json document(cJSON_Parse(io.lease), cJSON_Delete);
    ASSERT_NE(document, nullptr);
    cJSON *lease = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(document.get(), "leases"), 0);
    EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(lease, "prefix")), "2001:db8::/56");
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseReportsOpenFailure)
{
    io.lease_exists = true;
    io.lease_write_fails = true;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, nullptr, 0), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseReportsFailureCreatingMissingFile)
{
    io.lease_write_fails = true;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, nullptr, 0), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseRejectsServerIdentifierWithoutAddressBytes)
{
    duid_ll_t duid{3, 1, nullptr};
    io.lease_exists = true;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, &duid, 6), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseRejectsOutOfRangePrefixLength)
{
    IAPD_t iapd{};
    iapd.prefix_length = 129;
    io.lease_exists = true;
    EXPECT_EQ(writeLease(nullptr, &iapd, interface_name, nullptr, 0), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseHandlesDuidAllocationFailure)
{
    uint8_t mac[] = {1, 2, 3, 4, 5, 6};
    duid_ll_t duid{3, 1, mac};
    io.lease_exists = true;
    io.failed_malloc_size = (sizeof(mac) + 4) * 3 + 1;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, &duid, sizeof(mac)), -1);
    EXPECT_EQ(io.failed_malloc_size, 0u);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseHandlesDuidHeaderFormatFailure)
{
    uint8_t mac[] = {1, 2, 3, 4, 5, 6};
    duid_ll_t duid{3, 1, mac};
    io.lease_exists = true;
    io.duid_format_failure = DuidFormatFailure::header;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, &duid, sizeof(mac)), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseHandlesDuidAddressByteFormatFailure)
{
    uint8_t mac[] = {1, 2, 3, 4, 5, 6};
    duid_ll_t duid{3, 1, mac};
    io.lease_exists = true;
    io.duid_format_failure = DuidFormatFailure::address_byte;
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, &duid, sizeof(mac)), -1);
}

TEST_F(DHCPv6FunctionsTest, WriteLeaseHandlesJsonPrintAllocationFailure)
{
    io.lease_exists = true;
    io.failed_malloc_size = 256; // Initial print buffer capacity in the bundled cJSON implementation.
    EXPECT_EQ(writeLease(nullptr, nullptr, interface_name, nullptr, 0), -1);
    EXPECT_EQ(io.failed_malloc_size, 0u);
}

TEST_F(DHCPv6FunctionsTest, DeleteLeaseRemovesPathForInterface)
{
    delete_lease_file(interface_name);
    EXPECT_EQ(io.removed_path, lease_path);
}

TEST_F(DHCPv6FunctionsTest, RemoveAddressesSkipsOptionsWithNoAddress)
{
    io.mock_process = true;
    dhcpv6_option_t option{};
    option.option_code = IA_PD_OPTION_CODE;
    dhcpv6_message_t message{};
    message.option_list = &option;
    message.option_count = 1;
    remove_message_addresses(&message, interface_name);
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsTest, RemoveAddressesWaitsForOneChildPerAddress)
{
    io.mock_process = true;
    dhcpv6_option_t options[2]{};
    for (auto &option : options) {
        option.option_code = IA_ADDR_OPTION_CODE;
        option.ia_address_t.ipv6_address = 1;
    }
    dhcpv6_message_t message{};
    message.option_list = options;
    message.option_count = 2;
    remove_message_addresses(&message, interface_name);
    EXPECT_EQ(io.forks, 2);
    EXPECT_EQ(io.waited_for, 42);
}

TEST_F(DHCPv6FunctionsTest, RemoveAddressesSkipsAddressWhenForkFails)
{
    io.mock_process = true;
    io.child_pid = -1;
    dhcpv6_option_t option{};
    option.option_code = IA_ADDR_OPTION_CODE;
    option.ia_address_t.ipv6_address = 1;
    dhcpv6_message_t message{};
    message.option_list = &option;
    message.option_count = 1;
    remove_message_addresses(&message, interface_name);
    EXPECT_EQ(io.forks, 1);
    EXPECT_EQ(io.waited_for, -1);
}

TEST_F(DHCPv6FunctionsTest, RemoveAddressesSkipsAddressWhenTextConversionFails)
{
    io.mock_process = true;
    io.conversion_fails = true;
    dhcpv6_option_t option{};
    option.option_code = IA_ADDR_OPTION_CODE;
    option.ia_address_t.ipv6_address = 1;
    dhcpv6_message_t message{};
    message.option_list = &option;
    message.option_count = 1;
    remove_message_addresses(&message, interface_name);
    EXPECT_EQ(io.forks, 0);
}

TEST_F(DHCPv6FunctionsDeathTest, RemoveAddressChildExitsWhenCommandCannotExecute)
{
    dhcpv6_option_t option{};
    option.option_code = IA_ADDR_OPTION_CODE;
    option.ia_address_t.ipv6_address = 1;
    dhcpv6_message_t message{};
    message.option_list = &option;
    message.option_count = 1;
    EXPECT_EXIT({
        io.mock_process = true;
        io.child_pid = 0;
        remove_message_addresses(&message, interface_name);
    }, testing::ExitedWithCode(127), "");
}

TEST_F(DHCPv6FunctionsDeathTest, RemoveAddressChildHandlesUnavailableNullDevice)
{
    dhcpv6_option_t option{};
    option.option_code = IA_ADDR_OPTION_CODE;
    option.ia_address_t.ipv6_address = 1;
    dhcpv6_message_t message{};
    message.option_list = &option;
    message.option_count = 1;
    EXPECT_EXIT({
        io.mock_process = true;
        io.child_pid = 0;
        io.null_device_open_fails = true;
        remove_message_addresses(&message, interface_name);
    }, testing::ExitedWithCode(127), "");
}

TEST_F(DHCPv6FunctionsTest, RenewsAllowedIsZeroForEmptyWindow)
{
    EXPECT_EQ(renewsAllowed(0), 0);
}

TEST_F(DHCPv6FunctionsTest, RenewsAllowedCapsMaximumWindow)
{
    EXPECT_EQ(renewsAllowed(UINT32_MAX), RENEW_RETRANS_COUNT);
}

TEST_F(DHCPv6FunctionsTest, WaitToRetransmitSkipsDelayWithinReceiveTime)
{
    waitToRetransmit(999);
    EXPECT_TRUE(io.sleeps.empty());
}

TEST_F(DHCPv6FunctionsTest, WaitToRetransmitSleepsOnlyForRemainingTime)
{
    waitToRetransmit(1250);
    EXPECT_EQ(io.sleeps, std::vector<useconds_t>{250000});
}

class MatchingReplyTest : public testing::Test {
protected:
    void SetUp() override { request.transaction_id = 0x010203; }

    dhcpv6_message_t request{};
    Packet packet{REPLY_MESSAGE_TYPE, 1, 2, 3,
                  0, CLIENT_ID_OPTION_CODE, 0, 1, 4,
                  0, SERVER_ID_OPTION_CODE, 0, 1, 5};
};

TEST_F(MatchingReplyTest, AcceptsMatchingTransactionWithBothIdentifiers)
{
    EXPECT_TRUE(is_matching_reply(packet.data(), packet.size(), &request));
}

TEST_F(MatchingReplyTest, RejectsMissingServerIdentifier)
{
    EXPECT_FALSE(is_matching_reply(packet.data(), packet.size() - 5, &request));
}

TEST_F(MatchingReplyTest, RejectsTruncatedIdentifierValue)
{
    EXPECT_FALSE(is_matching_reply(packet.data(), packet.size() - 1, &request));
}

TEST_F(MatchingReplyTest, RejectsTruncatedTransactionId)
{
    EXPECT_FALSE(is_matching_reply(packet.data(), 3, &request));
}

TEST_F(MatchingReplyTest, RejectsDifferentTransactionId)
{
    ++request.transaction_id;
    EXPECT_FALSE(is_matching_reply(packet.data(), packet.size(), &request));
}

TEST_F(MatchingReplyTest, RejectsMissingClientIdentifier)
{
    packet = {REPLY_MESSAGE_TYPE, 1, 2, 3,
              0, SERVER_ID_OPTION_CODE, 0, 1, 5,
              0, PREFERENCE_OPTION_CODE, 0, 1, 10};
    EXPECT_FALSE(is_matching_reply(packet.data(), packet.size(), &request));
}

TEST_F(MatchingReplyTest, RejectsPartialTrailingOptionHeader)
{
    packet.push_back(0);
    EXPECT_FALSE(is_matching_reply(packet.data(), packet.size(), &request));
}
}
