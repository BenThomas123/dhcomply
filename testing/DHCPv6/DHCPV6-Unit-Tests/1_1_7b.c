#include "../../src/dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "1.1.7b: Testing that the NUT forms the Domain Search List option correctly in ORO \n");
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

    close(sockfd);
    return 0;
}