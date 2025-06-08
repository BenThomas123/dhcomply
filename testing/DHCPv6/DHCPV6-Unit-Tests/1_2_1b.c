#include "../../src/dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "1.2.1b: testing that the first retransmission of a solicit is correct\n");
    randomize();
    if (argc < 2)
    {
        exit(-1);
    }

    config_t *config_file = read_config_file(argv[1]);
    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);

    dhcpv6_message_t *firstSol = buildSolicit(config_file, argv[2]);
    sendSolicit(firstSol, sockfd, argv[2], 0);

    sendSolicit(firstSol, sockfd, argv[2], retrans_time / 10);

    close(sockfd);
    return 0;
}