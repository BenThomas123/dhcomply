#include "dhcomplyFunctions.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <config_file_path>\n", argv[0]);
        return 1;
    }

    config_t *config_file = read_config_file(argv[1]);
    int sockfd = setup_dhcpv6_socket("enp0s3");

    dhcpv6_message_t *firstSol = buildSolicit(config_file);
    sendSolicit(firstSol, sockfd, "enp0s3");

    uint8_t i = 0;
    while (i < 13)
    {
        uint16_t retrans_time = lower_solicit[i] + (rand() % (upper_solicit[i] - lower_solicit[i]));
        sleep(retrans_time / MILLISECONDS_IN_SECONDS);
        firstSol->option_list->elapsed_time_t.elapsed_time_value += retrans_time;
        sendSolicit(firstSol, sockfd, "enp0s3");
        i++;
    }

    close(sockfd);
    return 0;
}
