#include "dhcomplyLifeCycle.h"

int main(int argc, char *argv[]) {
    init_dhcomply();
    if (argc < 2)
    {
        exit(-1);
    }

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);
    if (!strcmp(argv[1], "C")) {

    }

    config_t *config_file = read_config_file(argv[1]);
    bool isStatless = config_file->na == false && config_file->pd == false;

    if (!isStatless) {
        statefulLifeCycle(config_file, argv[2], sockfd, argv[1]);
    } else {
        statelessLifeCycle(config_file, argv[2], sockfd);
    }

    close(sockfd);
    return 0;
}
