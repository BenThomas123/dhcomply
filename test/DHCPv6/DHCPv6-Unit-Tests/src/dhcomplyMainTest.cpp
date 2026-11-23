#include <gtest/gtest.h>

#include <string>
#include <vector>

extern "C" {
#include "dhcomplyLifeCycle.h"

int dhcomply_program_main(int argc, char **argv);
int __real_close(int fd);
int __real_socket(int family, int type, int protocol);
int __real_usleep(useconds_t duration);
void __real_valid_socket(int fd);
}

namespace {
enum class Step {
    initialize, config, find_lease, confirm, release, sleep,
    socket, validate_socket, bind, close, stateful, rapid_commit, stateless
};

constexpr int client_socket = 546;
constexpr char interface_name[] = "test0";

struct Scenario {
    bool active = false;
    bool has_lease = false;
    int confirm_status = 0;
    int release_status = 0;
    int socket_result = client_socket;
    int bind_error = 0;
    config_t config = {};
    std::string mode;
    std::vector<Step> steps;
};

Scenario scenario;

void record_dispatch(Step step, const config_t *config, const char *interface) {
    EXPECT_EQ(config, &scenario.config);
    EXPECT_STREQ(interface, interface_name);
    scenario.steps.push_back(step);
}

class MainTest : public testing::Test {
protected:
    void SetUp() override {
        scenario = {};
        scenario.active = true;
    }

    void TearDown() override { scenario = {}; }

    static int run(std::string mode) {
        char executable[] = "dhcomply";
        char interface[] = "test0";
        char *argv[] = {executable, mode.data(), interface, nullptr};
        return dhcomply_program_main(3, argv);
    }
};

using MainDeathTest = MainTest;
}

extern "C" {
void __wrap_init_dhcomply(void) {
    scenario.steps.push_back(Step::initialize);
}

config_t *__wrap_read_config_file(char *mode) {
    EXPECT_STREQ(mode, scenario.mode.c_str());
    scenario.steps.push_back(Step::config);
    return &scenario.config;
}

bool __wrap_leaseFileExists(const char *interface) {
    EXPECT_STREQ(interface, interface_name);
    scenario.steps.push_back(Step::find_lease);
    return scenario.has_lease;
}

int __wrap_confirmLifeCycle(config_t *config, char *interface) {
    record_dispatch(Step::confirm, config, interface);
    return scenario.confirm_status;
}

int __wrap_releaseLifeCycle(config_t *config, char *interface) {
    record_dispatch(Step::release, config, interface);
    return scenario.release_status;
}

int __wrap_usleep(useconds_t duration) {
    if (!scenario.active) {
        return __real_usleep(duration);
    }
    EXPECT_EQ(duration, 3000000u);
    scenario.steps.push_back(Step::sleep);
    return 0;
}

int __wrap_socket(int family, int type, int protocol) {
    if (!scenario.active) {
        return __real_socket(family, type, protocol);
    }
    EXPECT_EQ(family, AF_INET6);
    EXPECT_EQ(type, SOCK_DGRAM);
    EXPECT_EQ(protocol, IPPROTO_UDP);
    scenario.steps.push_back(Step::socket);
    if (scenario.socket_result < 0) {
        errno = EMFILE;
    }
    return scenario.socket_result;
}

void __wrap_valid_socket(int fd) {
    EXPECT_EQ(fd, scenario.socket_result);
    scenario.steps.push_back(Step::validate_socket);
    __real_valid_socket(fd);
}

int __wrap_bind_dhcpv6_client_socket(int fd) {
    EXPECT_EQ(fd, client_socket);
    scenario.steps.push_back(Step::bind);
    if (!scenario.bind_error) {
        return 0;
    }
    errno = scenario.bind_error;
    return -1;
}

int __wrap_close(int fd) {
    if (!scenario.active || fd != client_socket) {
        return __real_close(fd);
    }
    scenario.steps.push_back(Step::close);
    return 0;
}

void __wrap_statefulLifeCycle(config_t *config, char *interface, int fd, const char *mode) {
    EXPECT_EQ(fd, client_socket);
    EXPECT_STREQ(mode, scenario.mode.c_str());
    record_dispatch(Step::stateful, config, interface);
}

void __wrap_statefulLifeCycleRapidCommit(config_t *config, char *interface, int fd, char *mode) {
    EXPECT_EQ(fd, client_socket);
    EXPECT_STREQ(mode, scenario.mode.c_str());
    record_dispatch(Step::rapid_commit, config, interface);
}

void __wrap_statelessLifeCycle(config_t *config, const char *interface, int fd) {
    EXPECT_EQ(fd, client_socket);
    record_dispatch(Step::stateless, config, interface);
}
}

namespace {
TEST_F(MainDeathTest, ExitsWhenModeIsMissing) {
    char executable[] = "dhcomply";
    char *argv[] = {executable, nullptr};
    EXPECT_EXIT({
        dhcomply_program_main(1, argv);
        std::exit(42);
    }, testing::ExitedWithCode(255), "");
}

TEST_F(MainTest, RejectsModeWithoutInterfaceBeforeDispatch) {
    char executable[] = "dhcomply";
    char mode[] = "N";
    char *argv[] = {executable, mode, nullptr};
    EXPECT_EQ(dhcomply_program_main(2, argv), EXIT_FAILURE);
    EXPECT_EQ(scenario.steps, std::vector<Step>{Step::initialize});
}

TEST_F(MainDeathTest, HandlesVersionWithoutStartingDhcpv6) {
    scenario.mode = "V";
    EXPECT_EXIT({
        if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
            std::exit(42);
        }
        std::exit(run(scenario.mode));
    }, testing::ExitedWithCode(255), DHCOMPLY_CURRENT_VERSION);
}

TEST_F(MainDeathTest, ExitsWhenClientSocketCannotBeCreated) {
    scenario.mode = "S";
    scenario.socket_result = -1;
    EXPECT_EXIT(std::exit(run(scenario.mode)), testing::ExitedWithCode(255), "Invalid Socket");
}

TEST_F(MainTest, ReturnsReleaseStatus) {
    scenario.mode = "R";
    scenario.release_status = 1;
    EXPECT_EQ(run(scenario.mode), 1);
}

TEST_F(MainTest, ReleaseSkipsClientSocketSetup) {
    scenario.mode = "R";
    run(scenario.mode);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{Step::initialize, Step::config, Step::release}));
}

TEST_F(MainTest, ExplicitConfirmSkipsSocketSetupWhenComplete) {
    scenario.mode = "C";
    EXPECT_EQ(run(scenario.mode), 0);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::confirm, Step::sleep
    }));
}

TEST_F(MainTest, ExistingLeaseConfirmsBeforeFallbackToStatefulMode) {
    scenario.mode = "N";
    scenario.has_lease = true;
    scenario.confirm_status = 1;
    EXPECT_EQ(run(scenario.mode), 0);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::find_lease, Step::confirm, Step::sleep,
        Step::socket, Step::validate_socket, Step::bind, Step::stateful, Step::close
    }));
}

TEST_F(MainTest, BindsBeforeStartingStatefulMode) {
    scenario.mode = "N";
    scenario.config.na = true;
    EXPECT_EQ(run(scenario.mode), 0);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::find_lease, Step::socket,
        Step::validate_socket, Step::bind, Step::stateful, Step::close
    }));
}

TEST_F(MainTest, SelectsRapidCommitForPrefixDelegationWithRapidCommitEnabled) {
    scenario.mode = "P";
    scenario.config.pd = true;
    scenario.config.rapid_commit = true;
    EXPECT_EQ(run(scenario.mode), 0);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::find_lease, Step::socket,
        Step::validate_socket, Step::bind, Step::rapid_commit, Step::close
    }));
}

TEST_F(MainTest, BindsBeforeStartingStatelessMode) {
    scenario.mode = "S";
    EXPECT_EQ(run(scenario.mode), 0);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::find_lease, Step::socket,
        Step::validate_socket, Step::bind, Step::stateless, Step::close
    }));
}

TEST_F(MainTest, BindFailureReturnsFailure) {
    scenario.mode = "N";
    scenario.config.na = true;
    scenario.bind_error = EADDRINUSE;
    EXPECT_EQ(run(scenario.mode), EXIT_FAILURE);
}

TEST_F(MainTest, BindFailureStopsDispatchAfterClosingSocket) {
    scenario.mode = "N";
    scenario.config.na = true;
    scenario.bind_error = EADDRINUSE;
    run(scenario.mode);
    EXPECT_EQ(scenario.steps, (std::vector<Step>{
        Step::initialize, Step::config, Step::find_lease, Step::socket,
        Step::validate_socket, Step::bind, Step::close
    }));
}
}
