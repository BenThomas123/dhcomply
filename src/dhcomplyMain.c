#include "dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
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

    uint8_t retransmissionSolicit = 0;
    uint32_t elapse_time = 0;
    while (retransmissionSolicit < SOLICIT_RETRANS_COUNT) {
        uint32_t retrans_time = lower_solicit[retransmissionSolicit] + (rand() % (upper_solicit[retransmissionSolicit] - lower_solicit[retransmissionSolicit]));
        elapse_time += retrans_time;
        uint8_t *advertisement_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        bool advertisement_check = check_for_message(sockfd, advertisement_packet, ADVERTISE_MESSAGE_TYPE);
        if (advertisement_check) {
            dhcpv6_message_t *advertisement = parseAdvertisement(advertisement_packet, firstSol);
            dhcpv6_message_t *request = buildRequest(advertisement, config_file);
            sendRequest(request, sockfd, argv[2], 0);
            int retransmissionRequest = 0;
            elapse_time = 0;
            while (retransmissionRequest < REQUEST_RETRANS_COUNT) {
                uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                bool reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                if (reply_check) {
                    parseReply(reply_packet, request, argv[2]);
                }
                uint32_t retrans_time_request = lower_request[retransmissionRequest] + (rand() % (upper_request[retransmissionRequest] - lower_request[retransmissionRequest]));
                elapse_time += retrans_time_request;
                usleep(retrans_time_request * MILLISECONDS_IN_SECONDS);
                sendRequest(request, sockfd, argv[2], elapse_time / 10);
                retransmissionRequest++;
            }
            retransmissionSolicit = 0;
            elapse_time = 0;
        } else {
            usleep(retrans_time * MILLISECONDS_IN_SECONDS);
            if (retrans_time < 655360) {
                sendSolicit(firstSol, sockfd, argv[2], elapse_time / 10);
            } else {
                sendSolicit(firstSol, sockfd, argv[2], 65535);
            }
            retransmissionSolicit++;
        }
    }

    close(sockfd);
    return 0;
}
