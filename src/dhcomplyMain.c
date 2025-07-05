#include "dhcomplyFunctions.h"

int main(int argc, char *argv[])
{
    init_dhcomply();
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
        int advertisement_check = check_for_message(sockfd, advertisement_packet, ADVERTISE_MESSAGE_TYPE);
        if (advertisement_check) {
            dhcpv6_message_t *advertisement = parseAdvertisement(advertisement_packet, firstSol, advertisement_check);
            dhcpv6_message_t *request = buildRequest(advertisement, config_file);
            sendRequest(request, sockfd, argv[2], 0);
            int retransmissionRequest = 0;
            elapse_time = 0;
            while (retransmissionRequest < REQUEST_RETRANS_COUNT) {
                uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                if (reply_check) {
                    dhcpv6_message_t * reply_message = parseReply(reply_packet, request, argv[2], reply_check);
                    if (!reply_message) {
                        continue;
                    } else {
                        while (true) {
                            uint8_t na_index = 0;
                            uint8_t pd_index = 0;
                            int t1 = 0;
                            int t2 = 0;
                            if (reply_message == NULL) {
                                fprintf(stderr, "here at NULL");
                            }
                            if (!strcmp("NP", argv[1])) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);
                                t1 = min(reply_message->option_list[na_index].ia_na_t.t1, reply_message->option_list[pd_index].ia_pd_t.t1);
                                t2 = min(reply_message->option_list[na_index].ia_na_t.t2, reply_message->option_list[pd_index].ia_pd_t.t2);
                            } else if (!strcmp("N", argv[1])) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                t1 = reply_message->option_list[na_index].ia_na_t.t1;
                                t2 = reply_message->option_list[na_index].ia_na_t.t2;
                            } else {
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);
                                t1 = reply_message->option_list[pd_index].ia_pd_t.t1;
                                t2 = reply_message->option_list[pd_index].ia_pd_t.t2;
                            }
                            
                            dhcpv6_message_t * renew = buildRenew(reply_message, config_file);
                            time_t startRenew = time(NULL);
                            while (time(NULL) - startRenew < t1) {}
                            // waiting for declines, releases, reconfigures, confirms
                            sendRenew(renew, sockfd, argv[2], elapse_time);
                            uint8_t *reply_packet2 = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                            int reply_check2 = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                            if (reply_check2) {
                                reply_message = parseReply(reply_packet2, renew, argv[2], reply_check2);
                                continue;
                            }

                            int retransmissionRenew = 0;
                            elapse_time = 0;
                            
                            uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                            reply_check = 0;
                            time_t startRebind = time(NULL);
                            while (retransmissionRenew < maxRenewRetransmissions && reply_check == 0 && time(NULL) - startRebind < t2 - t1) {
                                uint32_t retrans_time_renew = renew_lower[retransmissionRenew] + (rand() % (renew_upper[retransmissionRenew] - renew_lower[retransmissionRenew]));
                                elapse_time += retrans_time_renew;
                                usleep(retrans_time_renew * MILLISECONDS_IN_SECONDS);
                                renew = buildRenew(reply_message, config_file);
                                sendRenew(renew, sockfd, argv[2], elapse_time / 10);
                                reply_check = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                retransmissionRenew++;
                            }
                            if (retransmissionRenew == maxRenewRetransmissions) {
                                break;
                            } else {
                                reply_message = parseReply(reply_packet2, renew, argv[2], reply_check);
                            }
                        }
                    }
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
