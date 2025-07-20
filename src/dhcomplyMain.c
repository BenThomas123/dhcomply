#include "dhcomplyFunctions.h"

int main(int argc, char *argv[]) {
    init_dhcomply();
    if (argc < 2)
    {
        exit(-1);
    }

    config_t *config_file = read_config_file(argv[1]);
    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);

    restart:

    dhcpv6_message_t *firstSol = buildSolicit(config_file, argv[2]);
    sendSolicit(firstSol, sockfd, argv[2], 0);

    int sol_max_rt = 3600 * MILLISECONDS_IN_SECONDS;

    uint8_t retransmissionSolicit = 0;
    uint32_t elapse_time = 0;
    while (retransmissionSolicit < SOLICIT_RETRANS_COUNT) {
        uint64_t retrans_time = lower_solicit[retransmissionSolicit] + (rand() % (upper_solicit[retransmissionSolicit] - lower_solicit[retransmissionSolicit]));
        elapse_time += retrans_time;
        uint8_t *advertisement_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int advertisement_check = check_for_message(sockfd, advertisement_packet, ADVERTISE_MESSAGE_TYPE);
        dhcpv6_message_t *advertisement = parseAdvertisement(advertisement_packet, firstSol, advertisement_check);
        int index = get_option_index(advertisement_packet, advertisement_check, SOL_MAX_RT_OPTION_CODE);
        if (index != -1) {
            sol_max_rt = advertisement->option_list[index].SOL_MAX_RT_t.SOL_MAX_RT_value * MILLISECONDS_IN_SECONDS;
            if (retrans_time > sol_max_rt) {
                retrans_time = sol_max_rt;
            }
        }
        if (advertisement_check && advertisement->valid) {
            dhcpv6_message_t *request = buildRequest(advertisement, config_file);
            sendRequest(request, sockfd, argv[2], 0);
            int retransmissionRequest = 0;
            elapse_time = 0;
            while (retransmissionRequest < REQUEST_RETRANS_COUNT) {
                uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                if (reply_check) {
                    dhcpv6_message_t *reply_message = parseReply(reply_packet, request, argv[2], reply_check);
                    if (!reply_message->valid) {
                        continue;
                    } else {
                        while (true) {
                            time_t startLease = time(NULL);
                            uint8_t na_index = 0;
                            uint8_t pd_index = 0;
                            int t1 = 0;
                            int t2 = 0;
                            int valid_lifetime = 0;
                            if (!strcmp("NP", argv[1])) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);
                                t1 = min(reply_message->option_list[na_index].ia_na_t.t1, reply_message->option_list[pd_index].ia_pd_t.t1);
                                t2 = min(reply_message->option_list[na_index].ia_na_t.t2, reply_message->option_list[pd_index].ia_pd_t.t2);
                                valid_lifetime = min(reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime, 
                                                     reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime);
                            } else if (!strcmp("N", argv[1])) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                t1 = reply_message->option_list[na_index].ia_na_t.t1;
                                t2 = reply_message->option_list[na_index].ia_na_t.t2;
                                valid_lifetime = reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime;
                            } else {
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);
                                t1 = reply_message->option_list[pd_index].ia_pd_t.t1;
                                t2 = reply_message->option_list[pd_index].ia_pd_t.t2;
                                valid_lifetime = reply_message->option_list[pd_index + 1].ia_address_t.valid_lifetime;
                            }

                            if (t1 == 0) {
                                t1 = 50;
                            }

                            if (t2 == 0) {
                                t2 = t1 + 30;
                            }
                            uint8_t *reply_packet2 = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));

                            if (check_dad_failure(argv[2])) {
                                dhcpv6_message_t *decline = buildDecline(reply_message, config_file);
                                sendDecline(decline, sockfd, argv[2], 0);
                                int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);

                                elapse_time = 0;
                                int declineRetransmission = 0;
                                while (!reply_check && declineRetransmission < DECLINE_RETRANS_COUNT) {
                                    uint32_t retrans_time_decline = decline_lower[declineRetransmission] + (rand() % (decline_upper[declineRetransmission] - decline_lower[declineRetransmission]));
                                    elapse_time += retrans_time_decline;
                                    usleep(retrans_time_decline * MILLISECONDS_IN_SECONDS);
                                    decline = buildDecline(reply_message, config_file);
                                    sendDecline(decline, sockfd, argv[2], elapse_time / 10);
                                    reply_check = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                    declineRetransmission++;
                                }
                                time_t restOfLife = time(NULL);
                                while (time(NULL) - startLease < valid_lifetime) {}

                                char cmd2[512];
                                snprintf(cmd2, "chmod +x rm -f /var/lib/dhcp/%s", "");
                                system(cmd2);
                                char cmd[512];
                                snprintf(cmd, "rm -f/var/lib/dhcp/lease_%s.json", argv[2]);
                                system(cmd);
                                goto restart;
                            }

                            while (time(NULL) - startLease < t1) {}
                            dhcpv6_message_t * renew = buildRenew(reply_message, config_file);
                            sendRenew(renew, sockfd, argv[2], 0);
                            int reply_check2 = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                            if (reply_check2) {
                                reply_message = parseReply(reply_packet2, renew, argv[2], reply_check2);
                                continue;
                            }

                            uint32_t retransmissionRenew = 0;
                            elapse_time = 0;
                            uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                            reply_check2 = 0;
                            time_t startRebind = time(NULL);
                            while (retransmissionRenew < maxRenewRetransmissions) {
                                uint32_t retrans_time_renew = renew_lower[retransmissionRenew] + (rand() % (renew_upper[retransmissionRenew] - renew_lower[retransmissionRenew]));
                                elapse_time += retrans_time_renew;
                                usleep(retrans_time_renew * MILLISECONDS_IN_SECONDS);
                                if (retrans_time_renew < 655360) {
                                    sendRenew(renew, sockfd, argv[2], elapse_time / 10);
                                } else {
                                    sendRenew(renew, sockfd, argv[2], 65536);
                                }
                                reply_check2 = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                if (reply_check2 != 0) {
                                    break;
                                }
                                retransmissionRenew++;
                            }
                            if (retransmissionRenew == maxRenewRetransmissions) {
                                int retransmissionRebind = 0;
                                elapse_time = 0;

                                while (time(NULL) - startLease < t2) {}

                                dhcpv6_message_t * rebind = buildRebind(reply_message, config_file);
                                sendRebind(rebind, sockfd, argv[2], 0);

                                reply_check = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                while (retransmissionRebind < REBIND_RETRANS_COUNT && time(NULL) - startLease < valid_lifetime) {
                                    uint32_t retrans_time_rebind = rebind_lower[retransmissionRebind] + (rand() % (rebind_upper[retransmissionRebind] - rebind_lower[retransmissionRebind]));
                                    elapse_time += retrans_time_rebind;
                                    usleep(retrans_time_rebind * MILLISECONDS_IN_SECONDS);
                                    if (retrans_time_rebind < 655360) {
                                        sendRebind(rebind, sockfd, argv[2], elapse_time / 10);
                                    } else {
                                        sendRebind(rebind, sockfd, argv[2], 65535);
                                    }
                                    reply_check = check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                    if (reply_check != 0) {
                                        break;
                                    }
                                    retransmissionRebind++;
                                }

                                if (!reply_check) {
                                    char cmd2[512];
                                    snprintf(cmd2, "chmod +x rm -f /var/lib/dhcp/%s", "");
                                    system(cmd2);
                                    char cmd[512];
                                    snprintf(cmd, "rm -f/var/lib/dhcp/lease_%s.json", argv[2]);
                                    system(cmd);
                                    goto restart;
                                } else {
                                    reply_message = parseReply(reply_packet2, rebind, argv[2], reply_check);
                                    continue;
                                }
                            } else {
                                reply_message = parseReply(reply_packet2, renew, argv[2], reply_check);
                                continue;
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
            if (elapse_time < 655350) {
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
