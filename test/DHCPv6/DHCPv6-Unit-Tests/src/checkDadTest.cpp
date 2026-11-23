#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

class CheckDadTest : public testing::Test {
protected:
    struct Result {
        int exit_status;
        std::string output;
    };

    void SetUp() override {
        char path[] = "/tmp/dhcomply-dad-tests-XXXXXX";
        ASSERT_NE(mkdtemp(path), nullptr);
        directory = path;

        write("ip", R"sh(#!/bin/sh
if [ "$#" -ne 4 ] || [ "$1 $2 $3" != "a show dev" ] || [ "$4" != "$DAD_INTERFACE" ]; then
    printf 'Unexpected ip arguments\n' >&2
    exit 64
fi
printf '%s\n' "$4" >> "$DAD_FIXTURE/queries"
count=$(wc -l < "$DAD_FIXTURE/queries")
state=$(sed -n "${count}p" "$DAD_FIXTURE/states")
if [ -z "$state" ]; then
    state=$(tail -n 1 "$DAD_FIXTURE/states")
fi
case "$state" in
    preferred|tentative|dadfailed) printf '    inet6 2001:db8::1/64 scope global %s\n' "$state" ;;
    competing) printf '    inet6 2001:db8::1/64 scope global tentative\n    inet6 2001:db8::2/64 scope global dadfailed\n' ;;
    missing) ;;
    error) printf 'Device not found\n' >&2; exit 1 ;;
    *) printf 'Unexpected fixture state\n' >&2; exit 65 ;;
esac
)sh");
        write("sleep", R"sh(#!/bin/sh
printf '%s\n' "$*" >> "$DAD_FIXTURE/sleeps"
)sh");
        ASSERT_EQ(chmod(path_for("ip").c_str(), 0700), 0);
        ASSERT_EQ(chmod(path_for("sleep").c_str(), 0700), 0);
        write("queries", "");
        write("sleeps", "");
    }

    void TearDown() override {
        if (!directory.empty()) {
            std::filesystem::remove_all(directory);
        }
    }

    void write(const char *name, const std::string &contents) {
        std::ofstream file(path_for(name));
        file << contents;
        file.close();
        ASSERT_TRUE(file);
    }

    std::string read(const char *name) const {
        std::ifstream file(path_for(name));
        EXPECT_TRUE(file);
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    Result run(const char *interface, const std::string &states) {
        write("states", states);
        const std::string search_path = directory + ":/usr/bin:/bin";
        const std::string output_path = path_for("output");
        pid_t child = fork();
        if (child < 0) {
            ADD_FAILURE() << "fork failed";
            return {-1, {}};
        }
        if (child == 0) {
            const int out = open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out < 0 || dup2(out, STDOUT_FILENO) < 0 || dup2(out, STDERR_FILENO) < 0 ||
                setenv("PATH", search_path.c_str(), 1) != 0 ||
                setenv("DAD_FIXTURE", directory.c_str(), 1) != 0 ||
                setenv("DAD_INTERFACE", interface ? interface : "", 1) != 0) {
                _exit(126);
            }
            if (out > STDERR_FILENO) {
                close(out);
            }
            execl("/bin/bash", "bash", DHCOMPLY_DAD_SCRIPT, interface, static_cast<char *>(nullptr));
            _exit(127);
        }

        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        EXPECT_EQ(waited, child);
        EXPECT_TRUE(WIFEXITED(status));
        if (waited == child && WIFEXITED(status)) {
            EXPECT_LT(WEXITSTATUS(status), 126) << "Could not start the DAD script";
        }
        return {waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1, read("output")};
    }

private:
    std::string path_for(const char *name) const { return directory + "/" + name; }
    std::string directory;
};

TEST_F(CheckDadTest, MissingInterfaceReturnsUsageError) {
    const auto result = run(nullptr, "preferred\n");
    EXPECT_EQ(result.exit_status, 1);
}

TEST_F(CheckDadTest, MissingInterfacePrintsUsage) {
    const auto result = run(nullptr, "preferred\n");
    EXPECT_NE(result.output.find("Usage:"), std::string::npos);
}

TEST_F(CheckDadTest, MissingInterfaceSkipsInterfaceQuery) {
    run(nullptr, "preferred\n");
    EXPECT_TRUE(read("queries").empty());
}

TEST_F(CheckDadTest, EmptyInterfaceReturnsUsageError) {
    const auto result = run("", "preferred\n");
    EXPECT_EQ(result.exit_status, 1);
}

TEST_F(CheckDadTest, EmptyInterfacePrintsUsage) {
    const auto result = run("", "preferred\n");
    EXPECT_NE(result.output.find("Usage:"), std::string::npos);
}

TEST_F(CheckDadTest, EmptyInterfaceSkipsInterfaceQuery) {
    run("", "preferred\n");
    EXPECT_TRUE(read("queries").empty());
}

TEST_F(CheckDadTest, DuplicateAddressReturnsFailure) {
    const auto result = run("test0", "dadfailed\n");
    EXPECT_EQ(result.exit_status, 2);
}

TEST_F(CheckDadTest, DuplicateAddressPrintsDiagnostic) {
    const auto result = run("test0", "dadfailed\n");
    EXPECT_EQ(result.output, "DAD failed on interface test0\n");
}

TEST_F(CheckDadTest, DuplicateAddressStopsPollingImmediately) {
    run("test0", "dadfailed\n");
    EXPECT_EQ(read("queries"), "test0\n");
    EXPECT_TRUE(read("sleeps").empty());
}

TEST_F(CheckDadTest, ReadyAddressReturnsSuccess) {
    const auto result = run("test0", "preferred\n");
    EXPECT_EQ(result.exit_status, 0);
}

TEST_F(CheckDadTest, ReadyAddressProducesNoDiagnostic) {
    const auto result = run("test0", "preferred\n");
    EXPECT_TRUE(result.output.empty());
}

TEST_F(CheckDadTest, ReadyAddressStopsPollingImmediately) {
    run("test0", "preferred\n");
    EXPECT_EQ(read("queries"), "test0\ntest0\n");
    EXPECT_TRUE(read("sleeps").empty());
}

TEST_F(CheckDadTest, MissingAddressReturnsSuccess) {
    const auto result = run("test0", "missing\n");
    EXPECT_EQ(result.exit_status, 0);
}

TEST_F(CheckDadTest, MissingAddressProducesNoDiagnostic) {
    const auto result = run("test0", "missing\n");
    EXPECT_TRUE(result.output.empty());
}

TEST_F(CheckDadTest, MissingAddressSkipsWait) {
    run("test0", "missing\n");
    EXPECT_TRUE(read("sleeps").empty());
}

TEST_F(CheckDadTest, TentativeAddressReturnsSuccessOnceReady) {
    const auto result = run("test0", "tentative\ntentative\npreferred\n");
    EXPECT_EQ(result.exit_status, 0);
}

TEST_F(CheckDadTest, TentativeAddressProducesNoDiagnosticOnceReady) {
    const auto result = run("test0", "tentative\ntentative\npreferred\n");
    EXPECT_TRUE(result.output.empty());
}

TEST_F(CheckDadTest, TentativeAddressIsPolledUntilReady) {
    run("test0", "tentative\ntentative\npreferred\n");
    EXPECT_EQ(read("sleeps"), "0.1\n");
    EXPECT_EQ(read("queries"), "test0\ntest0\ntest0\ntest0\n");
}

TEST_F(CheckDadTest, DuplicateAfterWaitingReturnsFailure) {
    const auto result = run("test0", "tentative\ntentative\ndadfailed\n");
    EXPECT_EQ(result.exit_status, 2);
}

TEST_F(CheckDadTest, DuplicateAfterWaitingPrintsDiagnostic) {
    const auto result = run("test0", "tentative\ntentative\ndadfailed\n");
    EXPECT_EQ(result.output, "DAD failed on interface test0\n");
}

TEST_F(CheckDadTest, DuplicateAfterWaitingStopsFurtherPolling) {
    run("test0", "tentative\ntentative\ndadfailed\n");
    EXPECT_EQ(read("sleeps"), "0.1\n");
    EXPECT_EQ(read("queries"), "test0\ntest0\ntest0\n");
}

TEST_F(CheckDadTest, PollLimitReturnsSuccess) {
    const auto result = run("test0", "tentative\n");
    EXPECT_EQ(result.exit_status, 0);
}

TEST_F(CheckDadTest, PollLimitProducesNoDiagnostic) {
    const auto result = run("test0", "tentative\n");
    EXPECT_TRUE(result.output.empty());
}

TEST_F(CheckDadTest, BoundsWaitingAtThirtyPolls) {
    run("test0", "tentative\n");
    std::string sleeps;
    std::string queries;
    for (int poll = 0; poll < 30; ++poll) {
        sleeps += "0.1\n";
        queries += "test0\ntest0\n";
    }
    EXPECT_EQ(read("sleeps"), sleeps);
    EXPECT_EQ(read("queries"), queries);
}

TEST_F(CheckDadTest, DuplicateOnLastPollReturnsFailure) {
    std::string states;
    for (int poll = 0; poll < 29; ++poll) {
        states += "tentative\ntentative\n";
    }
    const auto result = run("test0", states + "dadfailed\n");
    EXPECT_EQ(result.exit_status, 2);
}

TEST_F(CheckDadTest, DuplicateOnLastPollPrintsDiagnostic) {
    std::string states;
    for (int poll = 0; poll < 29; ++poll) {
        states += "tentative\ntentative\n";
    }
    const auto result = run("test0", states + "dadfailed\n");
    EXPECT_EQ(result.output, "DAD failed on interface test0\n");
}

TEST_F(CheckDadTest, DuplicateOnLastPollStopsBeforeFinalSleep) {
    std::string states;
    std::string sleeps;
    for (int poll = 0; poll < 29; ++poll) {
        states += "tentative\ntentative\n";
        sleeps += "0.1\n";
    }
    run("test0", states + "dadfailed\n");
    EXPECT_EQ(read("sleeps"), sleeps);
}

TEST_F(CheckDadTest, PrioritizesFailureOverAnotherTentativeAddress) {
    const auto result = run("test0", "competing\n");
    EXPECT_EQ(result.exit_status, 2);
    EXPECT_EQ(read("queries"), "test0\n");
    EXPECT_TRUE(read("sleeps").empty());
}

TEST_F(CheckDadTest, PassesInterfaceAsOneArgument) {
    const auto result = run("test interface", "dadfailed\n");
    EXPECT_EQ(result.exit_status, 2);
    EXPECT_EQ(read("queries"), "test interface\n");
}

TEST_F(CheckDadTest, DiagnosticPreservesInterfaceWithSpaces) {
    const auto result = run("test interface", "dadfailed\n");
    EXPECT_EQ(result.output, "DAD failed on interface test interface\n");
}

TEST_F(CheckDadTest, IncludesIpDiagnosticsWhenQueryFails) {
    const auto result = run("test0", "error\n");
    EXPECT_EQ(result.output, "Device not found\nDevice not found\n");
}

TEST_F(CheckDadTest, FailedQueryWithEmptyListingReturnsSuccess) {
    const auto result = run("test0", "error\n");
    // The current script treats an empty address listing as no tentative address.
    EXPECT_EQ(result.exit_status, 0);
}

TEST_F(CheckDadTest, FailedQueryWithEmptyListingSkipsWait) {
    run("test0", "error\n");
    EXPECT_TRUE(read("sleeps").empty());
}

}
