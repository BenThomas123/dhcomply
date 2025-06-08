#include "../../src/dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "1.2.1a: Testing that the NUT forms the solicit correctly\n");
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

    uint8_t retransmission = 0;
    while (retransmission < SOLICIT_RETRANS_COUNT)
    {
        uint32_t retrans_time = lower_solicit[retransmission] + (rand() % (upper_solicit[retransmission] - lower_solicit[retransmission]));
        usleep(retrans_time * MILLISECONDS_IN_SECONDS);
        sendSolicit(firstSol, sockfd, argv[2], retrans_time / 10);
        retransmission++;
    }

    close(sockfd);
    return 0;
}