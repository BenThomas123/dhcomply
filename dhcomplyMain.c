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

int setup_dhcpv6_socket(const char *iface_name)
{
    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in6 client_addr = {0};
    client_addr.sin6_family = AF_INET6;
    client_addr.sin6_port = htons(DHCP_CLIENT_PORT);
    client_addr.sin6_addr = in6addr_any;

    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    unsigned int ifindex = if_nametoindex(iface_name);
    if (ifindex == 0)
    {
        perror("if_nametoindex");
        exit(1);
    }

    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
    {
        perror("setsockopt IPV6_MULTICAST_IF");
        exit(1);
    }

    return sockfd;
}

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
