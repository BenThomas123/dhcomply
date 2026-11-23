#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include "dhcomplyStandardLibrary.h"
#include <sys/random.h>
}

namespace {
enum class Failure {
    none, open_read, open_write, seek, tell, read, write, stream,
    allocate, zero_allocate, duplicate, duplicate_result, address, remove, socket
};

Failure failure = Failure::none;
bool cross_device_rename = false;
std::string sandbox;
size_t random_calls = 0;
size_t random_bytes_written = 0;
int duplicate_calls = 0;
int last_socket = -1;
constexpr uint32_t random_value = 0xa753290du;
std::vector<int> random_steps;

bool reject(Failure expected, int error = EIO) {
    if (failure != expected) {
        return false;
    }
    errno = error;
    return true;
}

std::string fixture_path(const char *path) {
    const std::string_view name(path);
    if (name == "/etc/dhcomply.conf") {
        return sandbox.empty() ? std::string{} : sandbox + "/dhcomply.conf";
    }
    const bool lease = name.rfind("/var/lib/dhcp/lease_", 0) == 0;
    if (lease || name.rfind("/etc/lease_", 0) == 0) {
        const auto filename = name.substr(lease ? sizeof("/var/lib/dhcp/") - 1 : sizeof("/etc/") - 1);
        if (sandbox.empty() || filename.find('/') != std::string_view::npos) {
            return {};
        }
        return sandbox + (lease ? "/leases/" : "/") + std::string(filename);
    }
    return std::string(name);
}
}

extern "C" {
int __real_access(const char *, int);
FILE *__real_fopen(const char *, const char *);
int __real_rename(const char *, const char *);
int __real_remove(const char *);
int __real_fseek(FILE *, long, int);
long __real_ftell(FILE *);
size_t __real_fread(void *, size_t, size_t, FILE *);
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
int __real_ferror(FILE *);
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
char *__real_strdup(const char *);
const char *__real_inet_ntop(int, const void *, char *, socklen_t);
ssize_t __real_getrandom(void *, size_t, unsigned int);
int __real_socket(int, int, int);

int __wrap_access(const char *path, int mode) {
    return __real_access(fixture_path(path).c_str(), mode);
}

FILE *__wrap_fopen(const char *path, const char *mode) {
    if ((mode[0] == 'r' && reject(Failure::open_read)) ||
        (mode[0] == 'w' && reject(Failure::open_write))) {
        return nullptr;
    }
    return __real_fopen(fixture_path(path).c_str(), mode);
}

int __wrap_rename(const char *from, const char *to) {
    if (cross_device_rename) {
        errno = EXDEV;
        return -1;
    }
    return __real_rename(fixture_path(from).c_str(), fixture_path(to).c_str());
}

int __wrap_remove(const char *path) {
    return reject(Failure::remove) ? -1 : __real_remove(fixture_path(path).c_str());
}

int __wrap_fseek(FILE *file, long offset, int whence) {
    return reject(Failure::seek) ? -1 : __real_fseek(file, offset, whence);
}

long __wrap_ftell(FILE *file) {
    return reject(Failure::tell) ? -1 : __real_ftell(file);
}

size_t __wrap_fread(void *buf, size_t size, size_t count, FILE *file) {
    return reject(Failure::read) ? 0 : __real_fread(buf, size, count, file);
}

size_t __wrap_fwrite(const void *buf, size_t size, size_t count, FILE *file) {
    return reject(Failure::write) ? 0 : __real_fwrite(buf, size, count, file);
}

int __wrap_ferror(FILE *file) {
    return reject(Failure::stream) ? 1 : __real_ferror(file);
}

void *__wrap_malloc(size_t size) {
    if (reject(Failure::allocate, ENOMEM)) {
        failure = Failure::none;
        return nullptr;
    }
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size) {
    return reject(Failure::zero_allocate, ENOMEM) ? nullptr : __real_calloc(count, size);
}

char *__wrap_strdup(const char *value) {
    if (failure == Failure::duplicate_result && ++duplicate_calls == 2) {
        errno = ENOMEM;
        return nullptr;
    }
    return reject(Failure::duplicate, ENOMEM) ? nullptr : __real_strdup(value);
}

const char *__wrap_inet_ntop(int family, const void *address, char *text, socklen_t size) {
    return reject(Failure::address) ? nullptr : __real_inet_ntop(family, address, text, size);
}

ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags) {
    if (random_steps.empty()) {
        return __real_getrandom(buffer, length, flags);
    }
    if (random_calls >= random_steps.size() || flags != 0 ||
        length != sizeof(random_value) - random_bytes_written) {
        ADD_FAILURE() << "Unexpected getrandom request at byte " << random_bytes_written;
        errno = EIO;
        return -1;
    }
    int step = random_steps[random_calls++];
    if (step < 0) {
        errno = -step;
        return -1;
    }
    const auto count = static_cast<size_t>(step);
    if (count > length) {
        ADD_FAILURE() << "Scripted getrandom response exceeds requested length";
        errno = EIO;
        return -1;
    }
    const auto *bytes = reinterpret_cast<const unsigned char *>(&random_value);
    std::memcpy(buffer, bytes + random_bytes_written, count);
    random_bytes_written += count;
    return step;
}

int __wrap_socket(int family, int type, int protocol) {
    last_socket = reject(Failure::socket) ? -1 : __real_socket(family, type, protocol);
    return last_socket;
}
}

namespace {
using OwnedString = std::unique_ptr<char, decltype(&std::free)>;
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;

class StandardLibraryTest : public testing::Test {
protected:
    void TearDown() override {
        failure = Failure::none;
        cross_device_rename = false;
        random_steps.clear();
        random_calls = 0;
        random_bytes_written = 0;
        duplicate_calls = 0;
        last_socket = -1;
    }
};

using StandardLibraryDeathTest = StandardLibraryTest;

class FileTest : public StandardLibraryTest {
protected:
    void SetUp() override {
        char directory[] = "/tmp/dhcomply-tests-XXXXXX";
        ASSERT_NE(mkdtemp(directory), nullptr);
        sandbox = directory;
        ASSERT_TRUE(std::filesystem::create_directory(sandbox + "/leases"));
    }

    void TearDown() override {
        StandardLibraryTest::TearDown();
        if (!sandbox.empty()) {
            std::filesystem::remove_all(sandbox);
            sandbox.clear();
        }
    }

    const char *interface = "test0";
    const char *document = R"({"server_duid":{},"leases":[]})";

    std::string lease(const char *name = "test0") const {
        return sandbox + "/leases/lease_" + name + ".json";
    }
    std::string temporary() const { return sandbox + "/lease_test0.json"; }
    std::string config() const { return sandbox + "/dhcomply.conf"; }

    static void write(const std::string &path, const std::string &contents) {
        std::ofstream file(path, std::ios::binary);
        file << contents;
        file.close();
        ASSERT_TRUE(file);
    }

    static std::string read(const std::string &path) {
        std::ifstream file(path, std::ios::binary);
        EXPECT_TRUE(file);
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }
};

TEST_F(StandardLibraryDeathTest, ValidFilePointerAcceptsOpenFile) {
    std::unique_ptr<FILE, decltype(&std::fclose)> file(std::tmpfile(), std::fclose);
    ASSERT_NE(file, nullptr);
    EXPECT_EXIT({ valid_file_pointer(file.get()); std::exit(42); }, testing::ExitedWithCode(42), "");
}

TEST_F(StandardLibraryDeathTest, ValidFilePointerRejectsNull) {
    EXPECT_EXIT(valid_file_pointer(nullptr), testing::ExitedWithCode(255), "Invalid file pointer");
}

TEST_F(StandardLibraryDeathTest, ValidMemoryAllocationAcceptsNonNull) {
    int value = 0;
    EXPECT_EXIT({ valid_memory_allocation(&value); std::exit(42); }, testing::ExitedWithCode(42), "");
}

TEST_F(StandardLibraryDeathTest, ValidMemoryAllocationRejectsNull) {
    EXPECT_EXIT(valid_memory_allocation(nullptr), testing::ExitedWithCode(255), "memory was not able");
}

TEST_F(StandardLibraryDeathTest, ValidSocketAcceptsZero) {
    EXPECT_EXIT({ valid_socket(0); std::exit(42); }, testing::ExitedWithCode(42), "");
}

TEST_F(StandardLibraryDeathTest, ValidSocketRejectsNegativeDescriptor) {
    EXPECT_EXIT(valid_socket(-1), testing::ExitedWithCode(255), "Invalid Socket");
}

TEST_F(StandardLibraryDeathTest, PacketSentSuccessfullyAcceptsZero) {
    EXPECT_EXIT({ packet_sent_sucessfully(0); std::exit(42); }, testing::ExitedWithCode(42), "");
}

TEST_F(StandardLibraryDeathTest, PacketSentSuccessfullyAcceptsLargestPositiveCount) {
    EXPECT_EXIT({
        packet_sent_sucessfully(std::numeric_limits<ssize_t>::max());
        std::exit(42);
    }, testing::ExitedWithCode(42), "");
}

TEST_F(StandardLibraryDeathTest, PacketSentSuccessfullyRejectsNegativeResult) {
    EXPECT_EXIT(packet_sent_sucessfully(-1), testing::ExitedWithCode(255), "Packet was not sent");
}

TEST_F(FileTest, ExecuteFormattedCommandRunsValidCommand) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), command.size() + 1, command.size());
    EXPECT_TRUE(std::filesystem::exists(config()));
}

TEST_F(FileTest, ExecuteFormattedCommandRejectsNegativeLength) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), command.size() + 1, -1);
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(FileTest, ExecuteFormattedCommandRejectsTruncatedCommand) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), command.size(), command.size());
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(FileTest, ExecuteFormattedCommandRejectsZeroCapacity) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), 0, 0);
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(FileTest, ExecuteFormattedCommandRejectsLengthLargerThanCapacity) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), command.size() - 1, command.size());
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(FileTest, ExecuteFormattedCommandRejectsNegativeLengthEvenWithMaximumCapacity) {
    const std::string command = "touch " + config();
    execute_formatted_command(command.c_str(), std::numeric_limits<size_t>::max(), -2);
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(StandardLibraryTest, TrimRemovesSurroundingWhitespace) {
    char text[] = " \talpha beta\r\n";
    char *result = trim(text);
    EXPECT_STREQ(result, "alpha beta");
}

TEST_F(StandardLibraryTest, TrimReturnsPointerIntoOriginalBuffer) {
    char text[] = "  alpha";
    char *result = trim(text);
    EXPECT_EQ(result, text + 2);
}

TEST_F(StandardLibraryTest, TrimReturnsTerminatorForWhitespaceOnly) {
    char text[] = " \t";
    EXPECT_EQ(trim(text), text + 2);
}

TEST_F(StandardLibraryTest, TrimAcceptsEmptyString) {
    char text[] = "";
    EXPECT_EQ(trim(text), text);
}

TEST_F(StandardLibraryTest, TrimPreservesSingleCharacter) {
    char text[] = "x";
    EXPECT_STREQ(trim(text), "x");
}

TEST_F(StandardLibraryTest, TrimPreservesInternalWhitespace) {
    char text[] = "alpha  \t beta";
    EXPECT_STREQ(trim(text), "alpha  \t beta");
}

TEST_F(StandardLibraryTest, TrimPreservesHighBitBytes) {
    char text[] = " \xc3\xa9\t";
    EXPECT_STREQ(trim(text), "\xc3\xa9");
}

TEST_F(StandardLibraryTest, TrimRemovesLeadingWhitespaceOnly) {
    char text[] = " \tx";
    EXPECT_STREQ(trim(text), "x");
}

TEST_F(StandardLibraryTest, TrimRemovesTrailingWhitespaceOnly) {
    char text[] = "x\r\n";
    EXPECT_STREQ(trim(text), "x");
}

TEST_F(StandardLibraryTest, SubstringCopiesRequestedRange) {
    OwnedString text(substring("abcdef", 1, 3), std::free);
    EXPECT_STREQ(text.get(), "bcd");
}

TEST_F(StandardLibraryTest, SubstringCopiesRangeEndingAtTerminator) {
    OwnedString text(substring("abcdef", 3, 3), std::free);
    EXPECT_STREQ(text.get(), "def");
}

TEST_F(StandardLibraryTest, SubstringClampsLengthAtEnd) {
    OwnedString text(substring("abcdef", 4, 20), std::free);
    EXPECT_STREQ(text.get(), "ef");
}

TEST_F(StandardLibraryTest, SubstringClampsLengthThatWouldOverflowStartPlusLength) {
    OwnedString text(substring("abc", 1, std::numeric_limits<size_t>::max()), std::free);
    EXPECT_STREQ(text.get(), "bc");
}

TEST_F(StandardLibraryTest, SubstringHandlesMaximumOffsetWithoutAllocating) {
    EXPECT_STREQ(substring("abc", std::numeric_limits<size_t>::max(), 1), "");
}

TEST_F(StandardLibraryTest, SubstringHandlesEmptyInput) {
    EXPECT_STREQ(substring("", 0, 1), "");
}

TEST_F(StandardLibraryTest, SubstringReturnsEmptyForOutOfRangeStart) {
    EXPECT_STREQ(substring("abc", 3, 1), "");
}

TEST_F(StandardLibraryTest, SubstringAllocatesEmptyResultForZeroLength) {
    OwnedString text(substring("abc", 1, 0), std::free);
    EXPECT_STREQ(text.get(), "");
}

TEST_F(StandardLibraryTest, SubstringReturnsNullWhenAllocationFails) {
    failure = Failure::allocate;
    EXPECT_EQ(substring("abc", 0, 2), nullptr);
}

TEST_F(StandardLibraryTest, SubstringToEndCopiesSuffix) {
    OwnedString text(substring_to_end("abc", 1), std::free);
    EXPECT_STREQ(text.get(), "bc");
}

TEST_F(StandardLibraryTest, SubstringToEndAcceptsTerminatorOffset) {
    OwnedString text(substring_to_end("abc", 3), std::free);
    EXPECT_STREQ(text.get(), "");
}

TEST_F(StandardLibraryTest, SubstringToEndRejectsOffsetPastTerminator) {
    EXPECT_EQ(substring_to_end("abc", 4), nullptr);
}

TEST_F(StandardLibraryTest, SubstringToEndRejectsMaximumOffset) {
    EXPECT_EQ(substring_to_end("abc", std::numeric_limits<size_t>::max()), nullptr);
}

TEST_F(StandardLibraryDeathTest, SubstringToEndExitsWhenAllocationFails) {
    EXPECT_EXIT({
        failure = Failure::allocate;
        substring_to_end("abc", 1);
    }, testing::ExitedWithCode(255), "memory was not able");
}

constexpr uint128_t address = (static_cast<uint128_t>(0x20010db8) << 96) | 0xabcd;

TEST_F(StandardLibraryTest, Uint128ToIpv6FormatsBytesInNetworkOrder) {
    char text[INET6_ADDRSTRLEN];
    ASSERT_EQ(uint128_to_ipv6_str(address, text, sizeof(text)), 0);
    EXPECT_STREQ(text, "2001:db8::abcd");
}

TEST_F(StandardLibraryTest, Uint128ToIpv6RejectsSmallBuffer) {
    char text[2];
    EXPECT_EQ(uint128_to_ipv6_str(address, text, sizeof(text)), -1);
}

TEST_F(StandardLibraryTest, Uint128ToIpv6FormatsZeroIntoExactFitBuffer) {
    char text[sizeof("::")];
    ASSERT_EQ(uint128_to_ipv6_str(0, text, sizeof(text)), 0);
    EXPECT_STREQ(text, "::");
}

TEST_F(StandardLibraryTest, Uint128ToIpv6PreservesAll128Bits) {
    char text[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")];
    ASSERT_EQ(uint128_to_ipv6_str(~static_cast<uint128_t>(0), text, sizeof(text)), 0);
    EXPECT_STREQ(text, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

TEST_F(StandardLibraryTest, Ipv6ToUint128DecodesNetworkOrder) {
    uint128_t value = 0;
    ASSERT_EQ(ipv6_str_to_uint128("2001:db8::abcd", &value), 0);
    EXPECT_TRUE(value == address);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsInvalidText) {
    uint128_t value = 42;
    EXPECT_EQ(ipv6_str_to_uint128("2001:::a", &value), -1);
    EXPECT_TRUE(value == 42);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsNullText) {
    uint128_t value;
    EXPECT_EQ(ipv6_str_to_uint128(nullptr, &value), -1);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsNullOutput) {
    EXPECT_EQ(ipv6_str_to_uint128("::1", nullptr), -1);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsInvalidTextWithNullOutput) {
    EXPECT_EQ(ipv6_str_to_uint128("2001:::a", nullptr), -1);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsBothNullArguments) {
    EXPECT_EQ(ipv6_str_to_uint128(nullptr, nullptr), -1);
}

TEST_F(StandardLibraryTest, Ipv6ToUint128ParsesMappedIpv4) {
    uint128_t value = 0;
    ASSERT_EQ(ipv6_str_to_uint128("::FFFF:192.0.2.1", &value), 0);
    EXPECT_TRUE(value == static_cast<uint128_t>(0xffffc0000201ULL));
}

TEST_F(StandardLibraryTest, Ipv6ToUint128ParsesMaximumAddress) {
    uint128_t value = 0;
    ASSERT_EQ(ipv6_str_to_uint128("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", &value), 0);
    EXPECT_TRUE(value == ~static_cast<uint128_t>(0));
}

TEST_F(StandardLibraryTest, Ipv6ToUint128RejectsZoneSuffix) {
    uint128_t value = 42;
    EXPECT_EQ(ipv6_str_to_uint128("fe80::1%lo", &value), -1);
    EXPECT_TRUE(value == 42);
}

TEST_F(StandardLibraryTest, AppendIpv6AddsAddressToEmptyList) {
    OwnedString text(append_ipv6_address_if_unique("", "::1"), std::free);
    EXPECT_STREQ(text.get(), "::1");
}

TEST_F(StandardLibraryTest, AppendIpv6AddsUniqueAddress) {
    OwnedString text(append_ipv6_address_if_unique("::1 ::2", "::3"), std::free);
    EXPECT_STREQ(text.get(), "::1 ::2 ::3");
}

TEST_F(StandardLibraryTest, AppendIpv6LeavesDuplicateOut) {
    OwnedString text(append_ipv6_address_if_unique("::1 ::2", "::2"), std::free);
    EXPECT_STREQ(text.get(), "::1 ::2");
}

TEST_F(StandardLibraryTest, AppendIpv6RejectsNullList) {
    EXPECT_EQ(append_ipv6_address_if_unique(nullptr, "::1"), nullptr);
}

TEST_F(StandardLibraryTest, AppendIpv6RejectsNullAddress) {
    EXPECT_EQ(append_ipv6_address_if_unique("::1", nullptr), nullptr);
}

TEST_F(StandardLibraryTest, AppendIpv6RejectsBothNullArguments) {
    EXPECT_EQ(append_ipv6_address_if_unique(nullptr, nullptr), nullptr);
}

TEST_F(StandardLibraryTest, AppendIpv6HandlesListDuplicationFailure) {
    failure = Failure::duplicate;
    EXPECT_EQ(append_ipv6_address_if_unique("::1", "::2"), nullptr);
}

TEST_F(StandardLibraryTest, AppendIpv6HandlesResultAllocationFailure) {
    failure = Failure::allocate;
    EXPECT_EQ(append_ipv6_address_if_unique("::1", "::2"), nullptr);
}

TEST_F(StandardLibraryTest, AppendIpv6HandlesDuplicateResultAllocationFailure) {
    failure = Failure::duplicate_result;
    OwnedString text(append_ipv6_address_if_unique("::1 ::2", "::2"), std::free);
    EXPECT_EQ(text, nullptr);
    EXPECT_EQ(duplicate_calls, 2);
}

TEST_F(StandardLibraryTest, AppendIpv6PreservesLongLists) {
    std::string list = "2001:db8::1";
    for (int address_number = 2; address_number <= 100; ++address_number) {
        list += " 2001:db8::" + std::to_string(address_number);
    }
    ASSERT_GT(list.size(), 1023u);
    OwnedString text(append_ipv6_address_if_unique(list.c_str(), "::1"), std::free);
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text.get(), list + " ::1");
}

TEST_F(StandardLibraryTest, AppendIpv6CopiesZoneSuffixLiterally) {
    OwnedString text(append_ipv6_address_if_unique("", "fe80::1%lo"), std::free);
    EXPECT_STREQ(text.get(), "fe80::1%lo");
}

TEST_F(StandardLibraryTest, FormatIpv6PrefixAcceptsMaximumLength) {
    OwnedString text(format_ipv6_prefix(128, address), std::free);
    EXPECT_STREQ(text.get(), "2001:db8::abcd/128");
}

TEST_F(StandardLibraryTest, FormatIpv6PrefixAcceptsDefaultRoute) {
    OwnedString text(format_ipv6_prefix(0, 0), std::free);
    EXPECT_STREQ(text.get(), "::/0");
}

TEST_F(StandardLibraryTest, FormatIpv6PrefixRejectsExcessiveLength) {
    EXPECT_EQ(format_ipv6_prefix(129, address), nullptr);
}

TEST_F(StandardLibraryTest, FormatIpv6PrefixHandlesConversionFailure) {
    failure = Failure::address;
    EXPECT_EQ(format_ipv6_prefix(64, address), nullptr);
}

TEST_F(StandardLibraryTest, FormatIpv6PrefixHandlesAllocationFailure) {
    failure = Failure::allocate;
    EXPECT_EQ(format_ipv6_prefix(64, address), nullptr);
}

TEST_F(FileTest, LeaseFileExistsFindsFile) {
    write(lease(), document);
    EXPECT_TRUE(leaseFileExists(interface));
}

TEST_F(FileTest, LeaseFileExistsFindsLongestLinuxInterfaceName) {
    const std::string name(IFNAMSIZ - 1, 'x');
    write(lease(name.c_str()), document);
    EXPECT_TRUE(leaseFileExists(name.c_str()));
}

TEST_F(FileTest, LeaseFileExistsReportsMissingFile) {
    EXPECT_FALSE(leaseFileExists(interface));
}

TEST_F(FileTest, LeaseFileExistsRejectsNullInterface) {
    EXPECT_FALSE(leaseFileExists(nullptr));
}

TEST_F(FileTest, CopyLeasePreservesAllBytes) {
    const std::string payload = std::string(4095, 'a') + std::string("\0tail", 5);
    write(lease(), payload);
    ASSERT_EQ(copyLeaseFileToConfirmTemp(interface), 0);
    EXPECT_EQ(read(temporary()), payload);
}

TEST_F(FileTest, CopyLeaseKeepsSourceFile) {
    write(lease(), document);
    ASSERT_EQ(copyLeaseFileToConfirmTemp(interface), 0);
    EXPECT_TRUE(std::filesystem::exists(lease()));
}

TEST_F(FileTest, CopyLeaseOfEmptyFileTruncatesExistingDestination) {
    write(lease(), "");
    write(temporary(), document);
    ASSERT_EQ(copyLeaseFileToConfirmTemp(interface), 0);
    EXPECT_EQ(std::filesystem::file_size(temporary()), 0u);
}

TEST_F(FileTest, CopyLeaseRejectsNullInterface) {
    EXPECT_EQ(copyLeaseFileToConfirmTemp(nullptr), -1);
}

TEST_F(FileTest, CopyLeaseReportsMissingSource) {
    EXPECT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
}

TEST_F(FileTest, CopyLeaseHandlesDestinationOpenFailure) {
    write(lease(), document);
    failure = Failure::open_write;
    EXPECT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
}

TEST_F(FileTest, CopyLeaseHandlesWriteFailure) {
    write(lease(), document);
    failure = Failure::write;
    EXPECT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
}

TEST_F(FileTest, CopyLeaseHandlesReadError) {
    write(lease(), document);
    failure = Failure::stream;
    EXPECT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
}

TEST_F(FileTest, CopyLeaseReportsBufferedWriteFailure) {
    write(lease(), document);
    std::filesystem::create_symlink("/dev/full", temporary());
    EXPECT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
}

TEST_F(FileTest, CopyLeaseRetainsSourceOnBufferedWriteFailure) {
    write(lease(), document);
    std::filesystem::create_symlink("/dev/full", temporary());
    ASSERT_EQ(copyLeaseFileToConfirmTemp(interface), -1);
    EXPECT_EQ(read(lease()), document);
}

TEST_F(FileTest, MoveLeaseRenamesTemporaryFile) {
    write(temporary(), document);
    ASSERT_EQ(moveConfirmTempLeaseFile(interface), 0);
    EXPECT_FALSE(std::filesystem::exists(temporary()));
    EXPECT_EQ(read(lease()), document);
}

TEST_F(FileTest, MoveLeaseRejectsNullInterface) {
    EXPECT_EQ(moveConfirmTempLeaseFile(nullptr), -1);
}

TEST_F(FileTest, MoveLeaseHandlesMissingSource) {
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
}

TEST_F(FileTest, MoveLeaseCopiesAcrossFilesystems) {
    write(temporary(), document);
    cross_device_rename = true;
    ASSERT_EQ(moveConfirmTempLeaseFile(interface), 0);
    EXPECT_FALSE(std::filesystem::exists(temporary()));
    EXPECT_EQ(read(lease()), document);
}

TEST_F(FileTest, MoveLeaseHandlesFallbackSourceOpenFailure) {
    write(temporary(), document);
    cross_device_rename = true;
    failure = Failure::open_read;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
}

TEST_F(FileTest, MoveLeaseHandlesFallbackDestinationOpenFailure) {
    write(temporary(), document);
    cross_device_rename = true;
    failure = Failure::open_write;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
}

TEST_F(FileTest, MoveLeaseHandlesFallbackReadError) {
    write(temporary(), document);
    cross_device_rename = true;
    failure = Failure::stream;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
}

TEST_F(FileTest, MoveLeaseHandlesFallbackShortWrite) {
    write(temporary(), document);
    cross_device_rename = true;
    failure = Failure::write;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
}

TEST_F(FileTest, MoveLeaseHandlesFallbackRemoveFailure) {
    write(temporary(), document);
    cross_device_rename = true;
    failure = Failure::remove;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
    EXPECT_EQ(read(lease()), document);
}

TEST_F(FileTest, MoveLeaseRetainsSourceWhenBufferedWriteFails) {
    write(temporary(), document);
    std::filesystem::create_symlink("/dev/full", lease());
    cross_device_rename = true;
    EXPECT_EQ(moveConfirmTempLeaseFile(interface), -1);
    EXPECT_EQ(read(temporary()), document);
}

TEST_F(FileTest, ReadLeaseParsesValidDocument) {
    write(lease(), document);
    Json json(readLease(interface), cJSON_Delete);
    ASSERT_NE(json, nullptr);
    EXPECT_TRUE(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(json.get(), "server_duid")));
    EXPECT_TRUE(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(json.get(), "leases")));
}

TEST_F(FileTest, ReadLeaseRejectsMissingFile) {
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseHandlesOpenFailure) {
    write(lease(), document);
    failure = Failure::open_read;
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseHandlesSeekFailure) {
    write(lease(), document);
    failure = Failure::seek;
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseHandlesTellFailure) {
    write(lease(), document);
    failure = Failure::tell;
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseHandlesAllocationFailure) {
    write(lease(), document);
    failure = Failure::zero_allocate;
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseHandlesShortRead) {
    write(lease(), document);
    failure = Failure::read;
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsMalformedJson) {
    write(lease(), "{");
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsEmptyFile) {
    write(lease(), "");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsTrailingData) {
    write(lease(), std::string(document) + "{}");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsEmbeddedNul) {
    write(lease(), std::string(document) + '\0' + "extra");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseAllowsTrailingWhitespace) {
    write(lease(), std::string(document) + " \t\r\n");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_NE(json, nullptr);
}

TEST_F(FileTest, ReadLeasePreservesLeaseContents) {
    write(lease(), R"({"server_duid":{},"leases":[{"address":"2001:db8::1"}]})");
    Json json(readLease(interface), cJSON_Delete);
    ASSERT_NE(json, nullptr);
    const auto *entries = cJSON_GetObjectItemCaseSensitive(json.get(), "leases");
    ASSERT_EQ(cJSON_GetArraySize(entries), 1);
    const auto *entry = cJSON_GetArrayItem(entries, 0);
    EXPECT_STREQ(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "address")), "2001:db8::1");
}

TEST_F(FileTest, ReadLeaseRejectsInvalidServerDuid) {
    write(lease(), R"({"server_duid":[],"leases":[]})");
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsInvalidLeases) {
    write(lease(), R"({"server_duid":{},"leases":{}})");
    EXPECT_EQ(readLease(interface), nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsBothInvalidFields) {
    write(lease(), R"({"server_duid":[],"leases":{}})");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsMissingServerDuid) {
    write(lease(), R"({"leases":[]})");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsMissingLeases) {
    write(lease(), R"({"server_duid":{}})");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(FileTest, ReadLeaseRejectsNonObjectRoot) {
    write(lease(), "[]");
    Json json(readLease(interface), cJSON_Delete);
    EXPECT_EQ(json, nullptr);
}

TEST_F(StandardLibraryTest, GetMacAddressReadsLoopback) {
    std::array<uint8_t, MAC_ADDRESS_LENGTH> mac;
    mac.fill(0xff);
    ASSERT_EQ(get_mac_address("lo", mac.data()), 0);
    EXPECT_TRUE(std::all_of(mac.begin(), mac.end(), [](uint8_t byte) { return byte == 0; }));
}

TEST_F(StandardLibraryTest, GetMacAddressClosesSocketAfterSuccessfulRead) {
    std::array<uint8_t, MAC_ADDRESS_LENGTH> mac;
    ASSERT_EQ(get_mac_address("lo", mac.data()), 0);
    ASSERT_GE(last_socket, 0);
    EXPECT_EQ(fcntl(last_socket, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST_F(StandardLibraryDeathTest, GetMacAddressRejectsMissingInterface) {
    std::array<uint8_t, MAC_ADDRESS_LENGTH> mac{};
    EXPECT_EXIT(get_mac_address("", mac.data()), testing::ExitedWithCode(255), "");
}

TEST_F(StandardLibraryDeathTest, GetMacAddressExitsOnSocketFailure) {
    failure = Failure::socket;
    std::array<uint8_t, MAC_ADDRESS_LENGTH> mac{};
    EXPECT_EXIT(get_mac_address("lo", mac.data()), testing::ExitedWithCode(255), "Invalid Socket");
}

TEST_F(FileTest, InitDhcomplyCreatesConfigFile) {
    init_dhcomply();
    EXPECT_TRUE(std::filesystem::is_regular_file(config()));
}

TEST_F(FileTest, InitDhcomplyPreservesExistingConfig) {
    write(config(), "existing");
    init_dhcomply();
    EXPECT_EQ(read(config()), "existing");
}

TEST_F(FileTest, InitDhcomplyHandlesDeniedCreation) {
    failure = Failure::open_write;
    init_dhcomply();
    EXPECT_FALSE(std::filesystem::exists(config()));
}

TEST_F(StandardLibraryTest, UnpredictableRandomReturnsCompleteRead) {
    random_steps = {sizeof(uint32_t)};
    EXPECT_EQ(unpredictable_random(), random_value);
    EXPECT_EQ(random_calls, 1u);
}

TEST_F(StandardLibraryTest, UnpredictableRandomRetriesEintr) {
    random_steps = {-EINTR, sizeof(uint32_t)};
    EXPECT_EQ(unpredictable_random(), random_value);
    EXPECT_EQ(random_calls, 2u);
}

TEST_F(StandardLibraryTest, UnpredictableRandomAccumulatesShortReads) {
    random_steps = {1, 1, 1, 1};
    EXPECT_EQ(unpredictable_random(), random_value);
    EXPECT_EQ(random_calls, sizeof(uint32_t));
}

TEST_F(StandardLibraryTest, UnpredictableRandomRetriesRepeatedEintrAfterPartialRead) {
    random_steps = {2, -EINTR, -EINTR, 2};
    EXPECT_EQ(unpredictable_random(), random_value);
    EXPECT_EQ(random_calls, 4u);
}

TEST_F(StandardLibraryDeathTest, UnpredictableRandomExitsOnPermanentError) {
    random_steps = {-EIO};
    EXPECT_EXIT(unpredictable_random(), testing::ExitedWithCode(EXIT_FAILURE), "getrandom failed");
}

TEST_F(StandardLibraryDeathTest, UnpredictableRandomRejectsZeroByteRead) {
    random_steps = {0};
    EXPECT_EXIT(unpredictable_random(), testing::ExitedWithCode(EXIT_FAILURE), "returned no data");
}

TEST_F(StandardLibraryDeathTest, UnpredictableRandomExitsOnPermanentErrorAfterPartialRead) {
    random_steps = {2, -EIO};
    EXPECT_EXIT(unpredictable_random(), testing::ExitedWithCode(EXIT_FAILURE), "getrandom failed");
}

TEST_F(StandardLibraryDeathTest, UnpredictableRandomRejectsZeroByteReadAfterPartialRead) {
    random_steps = {2, 0};
    EXPECT_EXIT(unpredictable_random(), testing::ExitedWithCode(EXIT_FAILURE), "returned no data");
}

TEST_F(StandardLibraryTest, MinReturnsFirstWhenSmaller) {
    EXPECT_EQ(min(-2, 5), -2);
}

TEST_F(StandardLibraryTest, MinReturnsSecondWhenSmaller) {
    EXPECT_EQ(min(5, -2), -2);
}

TEST_F(StandardLibraryTest, MinReturnsEqualValue) {
    EXPECT_EQ(min(5, 5), 5);
}

TEST_F(StandardLibraryTest, MinAcceptsIntegerExtremes) {
    EXPECT_EQ(min(std::numeric_limits<int>::max(), std::numeric_limits<int>::min()),
              std::numeric_limits<int>::min());
}

TEST_F(StandardLibraryDeathTest, ErrorLogWritesMessageToStderr) {
    EXPECT_EXIT({ errorLog("dhcomply test diagnostic"); std::exit(42); },
                testing::ExitedWithCode(42), "^dhcomply test diagnostic\n$");
}
}
