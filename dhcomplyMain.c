#include "dhcomplyFunctions.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>

int main() {
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in6 src = {0}, dest = {0};
    src.sin6_family = AF_INET6;
    src.sin6_port = htons(546);
    src.sin6_addr = in6addr_any;
    bind(sock, (struct sockaddr*)&src, sizeof(src));

    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(547);
    inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex("eth0");  // replace with your interface

    char msg[] = "DHCPv6 test";
    sendto(sock, msg, sizeof(msg), 0, (struct sockaddr*)&dest, sizeof(dest));

    return 0;
}


/*
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
}*/
