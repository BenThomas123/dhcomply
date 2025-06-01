#include "dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
    randomize();
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <config_file_path>\n", argv[0]);
        return 1;
    }

    config_t *config_file = read_config_file(argv[1]);
    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    dhcpv6_message_t *firstSol = buildSolicit(config_file);
    sendSolicit(firstSol, sockfd, "enp0s3", 0);

    uint8_t i = 0;
    while (i < 14)
    {
        uint32_t retrans_time = lower_solicit[i] + (rand() % (upper_solicit[i] - lower_solicit[i]));
        usleep(retrans_time * MILLISECONDS_IN_SECONDS);
        sendSolicit(firstSol, sockfd, "enp0s3", retrans_time / 10);
        i++;
    }

    close(sockfd);
    return 0;
}
