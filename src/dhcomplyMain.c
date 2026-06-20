#include "dhcomplyLifeCycle.h"

int main(int argc, char *argv[]) {
    init_dhcomply();
    if (argc < 2) {
        exit(-1);
    }

    config_t *config_file = read_config_file(argv[1]);
    bool isStatless = config_file->na == false && config_file->pd == false;

    int confirm_exit_status = 1;
    if (!strcmp(argv[1], "R")) {
        releaseLifeCycle(config_file, argv[2]);
    } else if (!strcmp(argv[1], "C") || leaseFileExists(argv[2])) {
        confirm_exit_status = confirmLifeCycle(config_file, argv[2]);
        isStatless = 0;
        usleep(3 * MICROSECONDS_IN_SECONDS);
    }

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);
    if (confirm_exit_status && strcmp(argv[1], "R")) {
        if (!isStatless) {
            if (config_file->rapid_commit) {
                statefulLifeCycleRapidCommit(config_file, argv[2], sockfd, argv[1]);
            } else {
                statefulLifeCycle(config_file, argv[2], sockfd, argv[1]);
            }
        } else {
            statelessLifeCycle(config_file, argv[2], sockfd);
        }
    }

    close(sockfd);
    fprintf(stderr, "socket closed\n");
    return 0;
}
