#include "dhcomplyLifeCycle.h"

void statefulLifeCycle(config_t *config_file, char *ifname, int sockfd, char *ia) {
    restart:
    dhcpv6_message_t *firstSol = buildSolicit(config_file, ifname);
    sendSolicit(firstSol, sockfd, ifname, 0);

    uint64_t sol_max_rt = 3600 * MILLISECONDS_IN_SECONDS;

    uint8_t retransmissionSolicit = 0;
    uint32_t elapse_time = 0;

    while (retransmissionSolicit < SOLICIT_RETRANS_COUNT) {
        uint64_t retrans_time =
            lower_solicit[retransmissionSolicit] +
            (rand() % (upper_solicit[retransmissionSolicit] - lower_solicit[retransmissionSolicit]));

        elapse_time += retrans_time;

        uint8_t *advertisement_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int advertisement_check =
            check_for_advertisement(sockfd, advertisement_packet, config_file);

        dhcpv6_message_t *advertisement =
            parseAdvertisement(advertisement_packet, firstSol, advertisement_check);

        int index = get_option_index(advertisement_packet, advertisement_check, SOL_MAX_RT_OPTION_CODE);

        if (index != -1) {
            sol_max_rt =
                advertisement->option_list[index].SOL_MAX_RT_t.SOL_MAX_RT_value *
                MILLISECONDS_IN_SECONDS;

            if (retrans_time > sol_max_rt) {
                retrans_time = sol_max_rt;
            }
        }

        if (advertisement_check && advertisement->valid) {
            dhcpv6_message_t *request = buildRequest(advertisement, config_file);

            index = get_option_index(advertisement_packet, advertisement_check, PREFERENCE_OPTION_CODE);

            uint16_t preference = 0;

            if (index != -1) {
                preference = advertisement->option_list[index].preference_t.preference_value;
            }

            if (preference != 255 && retransmissionSolicit) {
                usleep(MICROSECONDS_IN_SECONDS);
            }

            sendRequest(request, sockfd, ifname, 0);

            int retransmissionRequest = 0;
            elapse_time = 0;

            while (retransmissionRequest < REQUEST_RETRANS_COUNT) {
                uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);

                if (reply_check) {
                    dhcpv6_message_t *reply_message =
                        parseReply(reply_packet, request, ifname, reply_check);

                    if (reply_message == NULL) {
                        return;
                    } else if (!reply_message->valid) {
                        continue;
                    } else {
                        while (true) {
                            time_t startLease = time(NULL);

                            int na_index = 0;
                            int pd_index = 0;

                            int t1 = 0;
                            int t2 = 0;
                            int valid_lifetime = 0;

                            if (!strcmp("NP", ia)) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                                t1 = min(
                                    reply_message->option_list[na_index].ia_na_t.t1,
                                    reply_message->option_list[pd_index].ia_pd_t.t1
                                );

                                t2 = min(
                                    reply_message->option_list[na_index].ia_na_t.t2,
                                    reply_message->option_list[pd_index].ia_pd_t.t2
                                );

                                valid_lifetime = min(
                                    reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime,
                                    reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime
                                );
                            } else if (!strcmp("N", ia)) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);

                                t1 = reply_message->option_list[na_index].ia_na_t.t1;
                                t2 = reply_message->option_list[na_index].ia_na_t.t2;
                                valid_lifetime =
                                    reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime;
                            } else {
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                                t1 = reply_message->option_list[pd_index].ia_pd_t.t1;
                                t2 = reply_message->option_list[pd_index].ia_pd_t.t2;
                                valid_lifetime =
                                    reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime;
                            }

                            if (t1 == 0) {
								if (config_file->t1 == 0) {
									t1 = valid_lifetime * .5;
								} else {
									t1 = config_file->t1;
								}
                            }

                            if (t2 == 0) {
                                if (config_file->t2 == 0) {
									t2 = valid_lifetime * .8;
								} else {
									t2 = config_file->t2;
								}
                            }

                            uint8_t *reply_packet2 =
                                (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));

                            if (check_dad_failure(ifname)) {
                                dhcpv6_message_t *decline = buildDecline(reply_message, config_file);
                                remove_message_addresses(decline, ifname);
                                delete_lease_file(ifname);
                                sendDecline(decline, sockfd, ifname, 0);

                                int reply_check =
                                    check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                                bool decline_reply_received =
                                    is_matching_reply(reply_packet, reply_check, decline);

                                elapse_time = 0;
                                int declineRetransmission = 0;

                                while (!decline_reply_received &&
                                       declineRetransmission < DECLINE_RETRANS_COUNT) {
                                    uint32_t retrans_time_decline =
                                        decline_lower[declineRetransmission] +
                                        (rand() %
                                         (decline_upper[declineRetransmission] -
                                          decline_lower[declineRetransmission]));

                                    elapse_time += retrans_time_decline;

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    waitToRetransmit(retrans_time_decline);

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    sendDecline(decline, sockfd, ifname, elapse_time / 10);

                                    reply_check =
                                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                    decline_reply_received =
                                        is_matching_reply(reply_packet2, reply_check, decline);

                                    declineRetransmission++;
                                }

                                goto restart;
                            }

                            while (time(NULL) - startLease < t1) {
                                if (!leaseFileExists(ifname)) {
                                    return;
                                }
                                usleep(MICROSECONDS_IN_MILLISECONDS);
                            }

                            dhcpv6_message_t *renew = buildRenew(reply_message, request, config_file);
                            sendRenew(renew, sockfd, ifname, 0);

                            int reply_check2 =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                            if (reply_check2) {
                                reply_message =
                                    parseReply(reply_packet2, renew, ifname, reply_check2);
                                continue;
                            }

                            uint32_t retransmissionRenew = 0;
                            elapse_time = 0;

                            uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                            reply_check2 = 0;

                            while (retransmissionRenew < maxRenewRetransmissions) {
                                uint32_t retrans_time_renew =
                                    renew_lower[retransmissionRenew] +
                                    (rand() %
                                     (renew_upper[retransmissionRenew] -
                                      renew_lower[retransmissionRenew]));

                                if (!leaseFileExists(ifname)) {
                                    return;
                                }

                                elapse_time += retrans_time_renew;
                                waitToRetransmit(retrans_time_renew);

                                if (!leaseFileExists(ifname)) {
                                    return;
                                }

                                if (elapse_time < 655350) {
                                    sendRenew(renew, sockfd, ifname, elapse_time / 10);
                                } else {
                                    sendRenew(renew, sockfd, ifname, 65535);
                                }

                                reply_check2 =
                                    check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                if (reply_check2 != 0) {
                                    break;
                                }

                                retransmissionRenew++;
                            }

                            if (retransmissionRenew == maxRenewRetransmissions) {
                                int retransmissionRebind = 0;
                                elapse_time = 0;

                                while (time(NULL) - startLease < t2) {
                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }
                                    usleep(MICROSECONDS_IN_MILLISECONDS);
                                }

                                if (time(NULL) - startLease >= valid_lifetime) {
                                    delete_lease_file(ifname);

                                    goto restart;
                                }

                                dhcpv6_message_t *rebind =
                                    buildRebind(reply_message, config_file);

                                sendRebind(rebind, sockfd, ifname, 0);

                                reply_check =
                                    check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                while (retransmissionRebind < REBIND_RETRANS_COUNT &&
                                       time(NULL) - startLease < valid_lifetime &&
                                       !reply_check) {
                                    uint32_t retrans_time_rebind =
                                        rebind_lower[retransmissionRebind] +
                                        (rand() %
                                         (rebind_upper[retransmissionRebind] -
                                          rebind_lower[retransmissionRebind]));

                                    elapse_time += retrans_time_rebind;

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    waitToRetransmit(retrans_time_rebind);

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

									if (time(NULL) - startLease < valid_lifetime) {
		                                if (elapse_time < 655350) {
                                        	sendRebind(rebind, sockfd, ifname, elapse_time / 10);
        	                            } else {
            	                            sendRebind(rebind, sockfd, ifname, 65535);
                	                    }
									} else {
                    					break;
                  					}

                                    reply_check =
                                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                    if (reply_check) {
                                        break;
                                    }

                                    retransmissionRebind++;
                                }

                                if (!reply_check) {

                                    remove_message_addresses(rebind, ifname);
                                    delete_lease_file(ifname);

                                    retransmissionSolicit = 0;
                                    elapse_time = 0;
                                    goto restart;
                                } else {
                                    reply_message =
                                        parseReply(reply_packet2, rebind, ifname, reply_check);
                                    continue;
                                }
                            } else {
                                reply_message =
                                    parseReply(reply_packet2, renew, ifname, reply_check);
                                continue;
                            }
                        }
                    }
                }

                uint32_t retrans_time_request =
                    lower_request[retransmissionRequest] +
                    (rand() %
                     (upper_request[retransmissionRequest] -
                      lower_request[retransmissionRequest]));

                elapse_time += retrans_time_request;
                waitToRetransmit(retrans_time_request);
                sendRequest(request, sockfd, ifname, elapse_time / 10);

                retransmissionRequest++;
            }

            retransmissionSolicit = 0;
            elapse_time = 0;
			usleep(MICROSECONDS_IN_SECONDS);
			goto restart;
        } else {
            waitToRetransmit(retrans_time);

            if (elapse_time < 655350) {
                sendSolicit(firstSol, sockfd, ifname, elapse_time / 10);
            } else {
                sendSolicit(firstSol, sockfd, ifname, 65535);
            }

            retransmissionSolicit++;
        }
    }
}

void statefulLifeCycleRapidCommit(config_t *config_file, char *ifname, int sockfd, char *ia) {
    restart:
    dhcpv6_message_t *firstSol = buildSolicit(config_file, ifname);
    sendSolicit(firstSol, sockfd, ifname, 0);

    uint64_t sol_max_rt = 3600 * MILLISECONDS_IN_SECONDS;

    uint8_t retransmissionSolicit = 0;
    uint32_t elapse_time = 0;

    while (retransmissionSolicit < SOLICIT_RETRANS_COUNT) {
        uint64_t retrans_time =
            lower_solicit[retransmissionSolicit] +
            (rand() % (upper_solicit[retransmissionSolicit] - lower_solicit[retransmissionSolicit]));

        elapse_time += retrans_time;

        uint8_t *response_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int response_type = 0;
        int response_size =
            check_for_rapid_commit_message(sockfd, response_packet, &response_type);

        uint8_t *advertisement_packet = response_packet;
        uint8_t *reply_packet = response_packet;
        int advertisement_check =
            response_type == ADVERTISE_MESSAGE_TYPE ? response_size : 0;
        int reply_check =
            response_type == REPLY_MESSAGE_TYPE ? response_size : 0;

        dhcpv6_message_t *dhcpv6_message = NULL;
        uint8_t *dhcpv6_packet = NULL;
        int dhcpv6_check = 0;

        if (reply_check) {
            dhcpv6_message = parseReply(reply_packet, firstSol, ifname, reply_check);
            dhcpv6_packet = reply_packet;
            dhcpv6_check = reply_check;
        } else if (advertisement_check) {
            dhcpv6_message =
                parseAdvertisement(advertisement_packet, firstSol, advertisement_check);
            dhcpv6_packet = advertisement_packet;
            dhcpv6_check = advertisement_check;
        }

        int index = -1;

        if (dhcpv6_packet != NULL) {
            index = get_option_index(dhcpv6_packet, dhcpv6_check, SOL_MAX_RT_OPTION_CODE);
        }

        if (index != -1 && dhcpv6_message != NULL) {
            sol_max_rt =
                dhcpv6_message->option_list[index].SOL_MAX_RT_t.SOL_MAX_RT_value *
                MILLISECONDS_IN_SECONDS;

            if (retrans_time > sol_max_rt) {
                retrans_time = sol_max_rt;
            }
        }

        if (reply_check) {
            dhcpv6_message_t *reply_message = dhcpv6_message;

            if (reply_message == NULL) {
                return;
            } else if (!reply_message->valid) {
                continue;
            } else {
                while (true) {
                    time_t startLease = time(NULL);

                    int na_index = 0;
                    int pd_index = 0;

                    int t1 = 0;
                    int t2 = 0;
                    int valid_lifetime = 0;

                    if (!strcmp("NP", ia)) {
                        na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                        pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                        t1 = min(
                            reply_message->option_list[na_index].ia_na_t.t1,
                            reply_message->option_list[pd_index].ia_pd_t.t1
                        );

                        t2 = min(
                            reply_message->option_list[na_index].ia_na_t.t2,
                            reply_message->option_list[pd_index].ia_pd_t.t2
                        );

                        valid_lifetime = min(
                            reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime,
                            reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime
                        );
                    } else if (!strcmp("N", ia)) {
                        na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);

                        t1 = reply_message->option_list[na_index].ia_na_t.t1;
                        t2 = reply_message->option_list[na_index].ia_na_t.t2;
                        valid_lifetime =
                            reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime;
                    } else {
                        pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                        t1 = reply_message->option_list[pd_index].ia_pd_t.t1;
                        t2 = reply_message->option_list[pd_index].ia_pd_t.t2;
                        valid_lifetime =
                            reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime;
                    }

                    if (t1 == 0) {
                        if (config_file->t1 == 0) {
                            t1 = valid_lifetime * .5;
                        } else {
                            t1 = config_file->t1;
                        }
                    }

                    if (t2 == 0) {
                        if (config_file->t2 == 0) {
                            t2 = valid_lifetime * .8;
                        } else {
                            t2 = config_file->t2;
                        }
                    }

                    uint8_t *reply_packet2 =
                        (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));

                    if (check_dad_failure(ifname)) {
                        dhcpv6_message_t *decline = buildDecline(reply_message, config_file);
                        remove_message_addresses(decline, ifname);
                        delete_lease_file(ifname);
                        sendDecline(decline, sockfd, ifname, 0);

                        int reply_check =
                            check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                        bool decline_reply_received =
                            is_matching_reply(reply_packet, reply_check, decline);

                        elapse_time = 0;
                        int declineRetransmission = 0;

                        while (!decline_reply_received &&
                               declineRetransmission < DECLINE_RETRANS_COUNT) {
                            uint32_t retrans_time_decline =
                                decline_lower[declineRetransmission] +
                                (rand() %
                                 (decline_upper[declineRetransmission] -
                                  decline_lower[declineRetransmission]));

                            elapse_time += retrans_time_decline;

                            if (!leaseFileExists(ifname)) {
                                return;
                            }

                            waitToRetransmit(retrans_time_decline);

                            if (!leaseFileExists(ifname)) {
                                return;
                            }

                            sendDecline(decline, sockfd, ifname, elapse_time / 10);

                            reply_check =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                            decline_reply_received =
                                is_matching_reply(reply_packet2, reply_check, decline);

                            declineRetransmission++;
                        }

                        goto restart;
                    }

                    while (time(NULL) - startLease < t1) {
                        if (!leaseFileExists(ifname)) {
                            return;
                        }
                        usleep(MICROSECONDS_IN_MILLISECONDS);
                    }

                    dhcpv6_message_t *renew =
                        buildRenew(reply_message, firstSol, config_file);
                    sendRenew(renew, sockfd, ifname, 0);

                    int reply_check2 =
                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                    if (reply_check2) {
                        reply_message =
                            parseReply(reply_packet2, renew, ifname, reply_check2);
                        continue;
                    }

                    uint32_t retransmissionRenew = 0;
                    elapse_time = 0;

                    uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                    reply_check2 = 0;

                    while (retransmissionRenew < maxRenewRetransmissions) {
                        uint32_t retrans_time_renew =
                            renew_lower[retransmissionRenew] +
                            (rand() %
                             (renew_upper[retransmissionRenew] -
                              renew_lower[retransmissionRenew]));

                        if (!leaseFileExists(ifname)) {
                            return;
                        }

                        elapse_time += retrans_time_renew;
                        waitToRetransmit(retrans_time_renew);

                        if (!leaseFileExists(ifname)) {
                            return;
                        }

                        if (elapse_time < 655350) {
                            sendRenew(renew, sockfd, ifname, elapse_time / 10);
                        } else {
                            sendRenew(renew, sockfd, ifname, 65535);
                        }

                        reply_check2 =
                            check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                        if (reply_check2 != 0) {
                            break;
                        }

                        retransmissionRenew++;
                    }

                    if (retransmissionRenew == maxRenewRetransmissions) {
                        int retransmissionRebind = 0;
                        elapse_time = 0;

                        while (time(NULL) - startLease < t2) {
                            if (!leaseFileExists(ifname)) {
                                return;
                            }
                            usleep(MICROSECONDS_IN_MILLISECONDS);
                        }

                        if (time(NULL) - startLease >= valid_lifetime) {
                            delete_lease_file(ifname);

                            goto restart;
                        }

                        dhcpv6_message_t *rebind =
                            buildRebind(reply_message, config_file);

                        sendRebind(rebind, sockfd, ifname, 0);

                        reply_check =
                            check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                        while (retransmissionRebind < REBIND_RETRANS_COUNT &&
                               time(NULL) - startLease < valid_lifetime &&
                               !reply_check) {
                            uint32_t retrans_time_rebind =
                                rebind_lower[retransmissionRebind] +
                                (rand() %
                                 (rebind_upper[retransmissionRebind] -
                                  rebind_lower[retransmissionRebind]));

                            elapse_time += retrans_time_rebind;

                            if (!leaseFileExists(ifname)) {
                                return;
                            }

                            waitToRetransmit(retrans_time_rebind);

                            if (!leaseFileExists(ifname)) {
                                return;
                            }

                            if (time(NULL) - startLease < valid_lifetime) {
                                if (elapse_time < 655350) {
                                    sendRebind(rebind, sockfd, ifname, elapse_time / 10);
                                } else {
                                    sendRebind(rebind, sockfd, ifname, 65535);
                                }
                            } else {
                                break;
                              }

                            reply_check =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                            if (reply_check) {
                                break;
                            }

                            retransmissionRebind++;
                        }

                        if (!reply_check) {

                            remove_message_addresses(rebind, ifname);
                            delete_lease_file(ifname);

                            retransmissionSolicit = 0;
                            elapse_time = 0;
                            goto restart;
                        } else {
                            reply_message =
                                parseReply(reply_packet2, rebind, ifname, reply_check);
                            continue;
                        }
                    } else {
                        reply_message =
                            parseReply(reply_packet2, renew, ifname, reply_check2);
                        continue;
                    }
                }
            }
        } else if (advertisement_check && dhcpv6_message != NULL &&
                   dhcpv6_message->valid) {
            dhcpv6_message_t *request = buildRequest(dhcpv6_message, config_file);

            index =
                get_option_index(advertisement_packet, advertisement_check, PREFERENCE_OPTION_CODE);

            uint16_t preference = 0;

            if (index != -1) {
                preference =
                    dhcpv6_message->option_list[index].preference_t.preference_value;
            }

            if (preference != 255 && retransmissionSolicit) {
                usleep(MICROSECONDS_IN_SECONDS);
            }

            sendRequest(request, sockfd, ifname, 0);

            int retransmissionRequest = 0;
            elapse_time = 0;

            while (retransmissionRequest < REQUEST_RETRANS_COUNT) {
                uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
                int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);

                if (reply_check) {
                    dhcpv6_message_t *reply_message =
                        parseReply(reply_packet, request, ifname, reply_check);

                    if (reply_message == NULL) {
                        return;
                    } else if (!reply_message->valid) {
                        continue;
                    } else {
                        while (true) {
                            time_t startLease = time(NULL);

                            int na_index = 0;
                            int pd_index = 0;

                            int t1 = 0;
                            int t2 = 0;
                            int valid_lifetime = 0;

                            if (!strcmp("NP", ia)) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                                t1 = min(
                                    reply_message->option_list[na_index].ia_na_t.t1,
                                    reply_message->option_list[pd_index].ia_pd_t.t1
                                );

                                t2 = min(
                                    reply_message->option_list[na_index].ia_na_t.t2,
                                    reply_message->option_list[pd_index].ia_pd_t.t2
                                );

                                valid_lifetime = min(
                                    reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime,
                                    reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime
                                );
                            } else if (!strcmp("N", ia)) {
                                na_index = get_option_index(reply_packet, reply_check, IA_NA_OPTION_CODE);

                                t1 = reply_message->option_list[na_index].ia_na_t.t1;
                                t2 = reply_message->option_list[na_index].ia_na_t.t2;
                                valid_lifetime =
                                    reply_message->option_list[na_index + 1].ia_address_t.valid_lifetime;
                            } else {
                                pd_index = get_option_index(reply_packet, reply_check, IA_PD_OPTION_CODE);

                                t1 = reply_message->option_list[pd_index].ia_pd_t.t1;
                                t2 = reply_message->option_list[pd_index].ia_pd_t.t2;
                                valid_lifetime =
                                    reply_message->option_list[pd_index + 1].ia_prefix_t.valid_lifetime;
                            }

                            if (t1 == 0) {
                                if (config_file->t1 == 0) {
                                    t1 = valid_lifetime * .5;
                                } else {
                                    t1 = config_file->t1;
                                }
                            }

                            if (t2 == 0) {
                                if (config_file->t2 == 0) {
                                    t2 = valid_lifetime * .8;
                                } else {
                                    t2 = config_file->t2;
                                }
                            }

                            uint8_t *reply_packet2 =
                                (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));

                            if (check_dad_failure(ifname)) {
                                dhcpv6_message_t *decline = buildDecline(reply_message, config_file);
                                remove_message_addresses(decline, ifname);
                                delete_lease_file(ifname);
                                sendDecline(decline, sockfd, ifname, 0);

                                int reply_check =
                                    check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                                bool decline_reply_received =
                                    is_matching_reply(reply_packet, reply_check, decline);

                                elapse_time = 0;
                                int declineRetransmission = 0;

                                while (!decline_reply_received &&
                                       declineRetransmission < DECLINE_RETRANS_COUNT) {
                                    uint32_t retrans_time_decline =
                                        decline_lower[declineRetransmission] +
                                        (rand() %
                                         (decline_upper[declineRetransmission] -
                                          decline_lower[declineRetransmission]));

                                    elapse_time += retrans_time_decline;

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    waitToRetransmit(retrans_time_decline);

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    sendDecline(decline, sockfd, ifname, elapse_time / 10);

                                    reply_check =
                                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                                    decline_reply_received =
                                        is_matching_reply(reply_packet2, reply_check, decline);

                                    declineRetransmission++;
                                }

                                goto restart;
                            }

                            while (time(NULL) - startLease < t1) {
                                if (!leaseFileExists(ifname)) {
                                    return;
                                }
                                usleep(MICROSECONDS_IN_MILLISECONDS);
                            }

                            dhcpv6_message_t *renew = buildRenew(reply_message, request, config_file);
                            sendRenew(renew, sockfd, ifname, 0);

                            int reply_check2 =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                            if (reply_check2) {
                                reply_message =
                                    parseReply(reply_packet2, renew, ifname, reply_check2);
                                continue;
                            }

                            uint32_t retransmissionRenew = 0;
                            elapse_time = 0;

                            uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                            reply_check2 = 0;

                            while (retransmissionRenew < maxRenewRetransmissions) {
                                uint32_t retrans_time_renew =
                                    renew_lower[retransmissionRenew] +
                                    (rand() %
                                     (renew_upper[retransmissionRenew] -
                                      renew_lower[retransmissionRenew]));

                                if (!leaseFileExists(ifname)) {
                                    return;
                                }

                                elapse_time += retrans_time_renew;
                                waitToRetransmit(retrans_time_renew);

                                if (!leaseFileExists(ifname)) {
                                    return;
                                }

                                if (elapse_time < 655350) {
                                    sendRenew(renew, sockfd, ifname, elapse_time / 10);
                                } else {
                                    sendRenew(renew, sockfd, ifname, 65535);
                                }

                                reply_check2 =
                                    check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                if (reply_check2 != 0) {
                                    break;
                                }

                                retransmissionRenew++;
                            }

                            if (retransmissionRenew == maxRenewRetransmissions) {
                                int retransmissionRebind = 0;
                                elapse_time = 0;

                                while (time(NULL) - startLease < t2) {
                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }
                                    usleep(MICROSECONDS_IN_MILLISECONDS);
                                }

                                if (time(NULL) - startLease >= valid_lifetime) {
                                    delete_lease_file(ifname);

                                    goto restart;
                                }

                                dhcpv6_message_t *rebind =
                                    buildRebind(reply_message, config_file);

                                sendRebind(rebind, sockfd, ifname, 0);

                                reply_check =
                                    check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                while (retransmissionRebind < REBIND_RETRANS_COUNT &&
                                       time(NULL) - startLease < valid_lifetime &&
                                       !reply_check) {
                                    uint32_t retrans_time_rebind =
                                        rebind_lower[retransmissionRebind] +
                                        (rand() %
                                         (rebind_upper[retransmissionRebind] -
                                          rebind_lower[retransmissionRebind]));

                                    elapse_time += retrans_time_rebind;

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    waitToRetransmit(retrans_time_rebind);

                                    if (!leaseFileExists(ifname)) {
                                        return;
                                    }

                                    if (time(NULL) - startLease < valid_lifetime) {
                                        if (elapse_time < 655350) {
                                            sendRebind(rebind, sockfd, ifname, elapse_time / 10);
                                        } else {
                                            sendRebind(rebind, sockfd, ifname, 65535);
                                        }
                                    } else {
                                        break;
                                      }

                                    reply_check =
                                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                                    if (reply_check) {
                                        break;
                                    }

                                    retransmissionRebind++;
                                }

                                if (!reply_check) {

                                    remove_message_addresses(rebind, ifname);
                                    delete_lease_file(ifname);

                                    retransmissionSolicit = 0;
                                    elapse_time = 0;
                                    goto restart;
                                } else {
                                    reply_message =
                                        parseReply(reply_packet2, rebind, ifname, reply_check);
                                    continue;
                                }
                            } else {
                                reply_message =
                                    parseReply(reply_packet2, renew, ifname, reply_check2);
                                continue;
                            }
                        }
                    }
                }

                uint32_t retrans_time_request =
                    lower_request[retransmissionRequest] +
                    (rand() %
                     (upper_request[retransmissionRequest] -
                      lower_request[retransmissionRequest]));

                elapse_time += retrans_time_request;
                waitToRetransmit(retrans_time_request);
                sendRequest(request, sockfd, ifname, elapse_time / 10);

                retransmissionRequest++;
            }

            retransmissionSolicit = 0;
            elapse_time = 0;
            usleep(MICROSECONDS_IN_SECONDS);
            goto restart;
        } else {
            waitToRetransmit(retrans_time);

            if (elapse_time < 655350) {
                sendSolicit(firstSol, sockfd, ifname, elapse_time / 10);
            } else {
                sendSolicit(firstSol, sockfd, ifname, 65535);
            }

            retransmissionSolicit++;
        }
    }
}

int confirmLifeCycle(config_t *config_file, char *ifname) {

    if (!leaseFileExists(ifname)) {
        fprintf(stderr, "lease file does not exist\n");
        return 1;
    }

    fprintf(stdout, "here after lease file check\n");
    uint8_t retransmissionConfirm = 0;
    uint32_t elapse_time = 0;

    uint32_t t1 = 0;
    uint32_t t2 = 0;
    uint32_t valid_lifetime = 0;
    dhcpv6_message_t *firstConfirm = buildConfirm(config_file, ifname, &t1, &t2, &valid_lifetime);

    int a = copyLeaseFileToConfirmTemp(ifname);
    delete_lease_file(ifname);
    while (!dhcpv6_client_port_available()) {}
    fprintf(stdout, "other process shutdown, %d\n", a);
    int b = moveConfirmTempLeaseFile(ifname);
    fprintf(stdout, "moved file, %d\n", b);

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);

    sendConfirm(firstConfirm, sockfd, ifname, elapse_time);

    fprintf(stderr, "entering send confirm");
    while (retransmissionConfirm < CONFIRM_RETRANS_COUNT) {
        uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
        if (reply_check) {
            fprintf(stderr, "reply receieved");
            dhcpv6_message_t *reply_message =
                parseReply(reply_packet, firstConfirm, ifname, reply_check);
            if (reply_message == NULL) {
                return 1;
            } else if (!reply_message->valid) {
                fprintf(stderr, "invalid reply \n");
                continue;
            } else {
                fprintf(stderr, "valid reply \n");
                while (true) {
                    fprintf(stdout, "t1: %d t2: %d vl: %d\n", t1, t2, valid_lifetime);
                    time_t startLease = time(NULL);

                    uint8_t *reply_packet2 =
                        (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));

                    if (check_dad_failure(ifname)) {
                        dhcpv6_message_t *decline = buildDecline(reply_message, config_file);
                        remove_message_addresses(decline, ifname);
                        delete_lease_file(ifname);
                        sendDecline(decline, sockfd, ifname, 0);

                        int reply_check =
                            check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
                        bool decline_reply_received =
                            is_matching_reply(reply_packet, reply_check, decline);

                        elapse_time = 0;
                        int declineRetransmission = 0;

                        while (!decline_reply_received &&
                               declineRetransmission < DECLINE_RETRANS_COUNT) {
                            uint32_t retrans_time_decline =
                                decline_lower[declineRetransmission] +
                                (rand() %
                                 (decline_upper[declineRetransmission] -
                                  decline_lower[declineRetransmission]));

                            elapse_time += retrans_time_decline;
                            waitToRetransmit(retrans_time_decline);

                            sendDecline(decline, sockfd, ifname, elapse_time / 10);

                            reply_check =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);
                            decline_reply_received =
                                is_matching_reply(reply_packet2, reply_check, decline);

                            declineRetransmission++;
                        }

                        return 1;
                    }

                    while (time(NULL) - startLease < t1) {
                        if (!leaseFileExists(ifname)) {
                            return 0;
                        }
                        usleep(MICROSECONDS_IN_MILLISECONDS);
                    }

                    dhcpv6_message_t *renew = buildRenew(reply_message, firstConfirm, config_file);
                    sendRenew(renew, sockfd, ifname, 0);

                    int reply_check2 =
                        check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                    if (reply_check2) {
                        reply_message =
                            parseReply(reply_packet2, renew, ifname, reply_check2);
                        continue;
                    }

                    uint32_t retransmissionRenew = 0;
                    elapse_time = 0;

                    uint32_t maxRenewRetransmissions = renewsAllowed(t2 - t1);
                    reply_check2 = 0;

                    while (retransmissionRenew < maxRenewRetransmissions) {
                        uint32_t retrans_time_renew =
                            renew_lower[retransmissionRenew] +
                            (rand() %
                             (renew_upper[retransmissionRenew] -
                              renew_lower[retransmissionRenew]));

                        elapse_time += retrans_time_renew;

                        if (!leaseFileExists(ifname)) {
                            return 0;
                        }

                        waitToRetransmit(retrans_time_renew);

                        if (!leaseFileExists(ifname)) {
                            return 0;
                        }

                        if (elapse_time < 655350) {
                            sendRenew(renew, sockfd, ifname, elapse_time / 10);
                        } else {
                            sendRenew(renew, sockfd, ifname, 65535);
                        }

                        reply_check2 =
                            check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                        if (reply_check2 != 0) {
                            break;
                        }

                        retransmissionRenew++;
                    }

                    if (retransmissionRenew == maxRenewRetransmissions) {
                        int retransmissionRebind = 0;
                        elapse_time = 0;

                        while (time(NULL) - startLease < t2) {
                            if (!leaseFileExists(ifname)) {
                                return 0;
                            }
                            usleep(MICROSECONDS_IN_MILLISECONDS);
                        }

                        if (time(NULL) - startLease >= valid_lifetime) {
                            delete_lease_file(ifname);
                            return 1;
                        }

                        dhcpv6_message_t *rebind =
                            buildRebind(reply_message, config_file);

                        sendRebind(rebind, sockfd, ifname, 0);

                        reply_check =
                            check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                        while (retransmissionRebind < REBIND_RETRANS_COUNT &&
                               time(NULL) - startLease < valid_lifetime &&
                               !reply_check) {
                            uint32_t retrans_time_rebind =
                                rebind_lower[retransmissionRebind] +
                                (rand() %
                                 (rebind_upper[retransmissionRebind] -
                                  rebind_lower[retransmissionRebind]));

                            elapse_time += retrans_time_rebind;
                            waitToRetransmit(retrans_time_rebind);
                            if (time(NULL) - startLease < valid_lifetime) {
                                if (elapse_time < 655350) {
                                    sendRebind(rebind, sockfd, ifname, elapse_time / 10);
                                } else {
                                    sendRebind(rebind, sockfd, ifname, 65535);
                                }
                            } else {
                                break;
                            }

                            reply_check =
                                check_for_message(sockfd, reply_packet2, REPLY_MESSAGE_TYPE);

                            if (reply_check) {
                                break;
                            }

                            retransmissionRebind++;
                        }

                        if (!reply_check) {
                            remove_message_addresses(rebind, ifname);
                            delete_lease_file(ifname);

                            return 1;
                        } else {
                            reply_message =
                                parseReply(reply_packet2, rebind, ifname, reply_check);
                            continue;
                        }
                    } else {
                        reply_message =
                            parseReply(reply_packet2, renew, ifname, reply_check);
                        continue;
                    }
                }
            }
        } else {
           uint64_t retrans_time = confirm_lower[retransmissionConfirm] +
                    (rand() % (confirm_upper[retransmissionConfirm] - confirm_lower[retransmissionConfirm]));
           waitToRetransmit(retrans_time);
           if (elapse_time < 655350) {
                sendConfirm(firstConfirm, sockfd, ifname, elapse_time / 10);
           } else {
                sendConfirm(firstConfirm, sockfd, ifname, 65535);
           }
           retransmissionConfirm++;
        }
    }

    return 1;
}

int releaseLifeCycle(config_t *config_file, char *ifname) {
	fprintf(stderr, "in releaseLifeCycle...verifying lease file\n");

    if (!leaseFileExists(ifname)) {
        return 1;
    }

	fprintf(stderr, "in releaseLifeCycle\n");
    uint8_t retransmission_release = 0;
    uint32_t elapse_time = 0;

    copyLeaseFileToConfirmTemp(ifname);
    delete_lease_file(ifname);
    while (!dhcpv6_client_port_available()) {}
    moveConfirmTempLeaseFile(ifname);
	fprintf(stderr, "in releaseLifeCycle3\n");

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    valid_socket(sockfd);

    dhcpv6_message_t *firstRelease = buildRelease(config_file, ifname);
    sendRelease(firstRelease, sockfd, ifname, elapse_time);
	fprintf(stderr, "in releaseLifeCycle4\n");

    while (retransmission_release < RELEASE_RETRANS_COUNT) {
        uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);
        if (reply_check) {
            dhcpv6_message_t *reply_message =
                parseReply(reply_packet, firstRelease, ifname, reply_check);
            if (!reply_message->valid) {
				fprintf(stderr, "in releaseLifeCycle5\n");
                continue;
            } else {
				fprintf(stderr, "in releaseLifeCycle loop\n");
				remove_message_addresses(firstRelease, ifname);
                delete_lease_file(ifname);
                return 0;
            }
        } else {
           uint64_t retrans_time = release_lower[retransmission_release] +
                    (rand() % (release_upper[retransmission_release] - release_lower[retransmission_release]));
           waitToRetransmit(retrans_time);
           if (elapse_time < 655350) {
                sendRelease(firstRelease, sockfd, ifname, elapse_time / 10);
           } else {
                sendRelease(firstRelease, sockfd, ifname, 65535);
           }
           retransmission_release++;
        }
    }

    return 1;
}

void statelessLifeCycle(config_t *config_file, char *ifname, int sockfd) {
    restartStateless:
    uint64_t inf_max_rt = 3600 * MILLISECONDS_IN_SECONDS;
    uint32_t refresh_time = 86400 * MILLISECONDS_IN_SECONDS;

    while (true) {
        dhcpv6_message_t *firstInfoReq = buildInformationRequest(config_file, ifname);
        sendInformationRequest(firstInfoReq, sockfd, ifname, 0);

        uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
        int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);

        dhcpv6_message_t *reply_message =
            parseStatelessReply(reply_packet, firstInfoReq, ifname, reply_check);

        int index = get_option_index(reply_packet, reply_check, INFORMATION_REFRESH_OPTION_CODE);

        if (index != -1) {
            refresh_time =
                reply_message->option_list[index]
                    .information_refresh_time_t
                    .information_refresh_time *
                MILLISECONDS_IN_SECONDS;
        }

        index = get_option_index(reply_packet, reply_check, INF_MAX_RT_OPTION_CODE);

        if (index != -1) {
            inf_max_rt =
                reply_message->option_list[index]
                    .INF_MAX_RT_t
                    .INF_MAX_RT_value *
                MILLISECONDS_IN_SECONDS;
        }

        if (reply_check && reply_message->valid) {
            usleep(refresh_time * MICROSECONDS_IN_MILLISECONDS);
            goto restartStateless;
        }

        uint8_t retransmissionInfoReq = 0;
        uint32_t elapse_time = 0;

        while (retransmissionInfoReq < INFO_REQUEST_RETRANS_COUNT) {
            uint64_t retrans_time =
                lower_solicit[retransmissionInfoReq] +
                (rand() %
                 (upper_solicit[retransmissionInfoReq] -
                  lower_solicit[retransmissionInfoReq]));

            if (retrans_time > inf_max_rt) {
                retrans_time = inf_max_rt;
            }

            elapse_time += retrans_time;

            uint8_t *reply_packet = (uint8_t *)calloc(MAX_PACKET_SIZE, sizeof(uint8_t));
            int reply_check = check_for_message(sockfd, reply_packet, REPLY_MESSAGE_TYPE);

            dhcpv6_message_t *reply_message =
                parseStatelessReply(reply_packet, firstInfoReq, ifname, reply_check);

            if (reply_check && reply_message->valid) {
                int index =
                    get_option_index(reply_packet, reply_check, INFORMATION_REFRESH_OPTION_CODE);

                if (index != -1) {
                    refresh_time =
                        reply_message->option_list[index]
                            .information_refresh_time_t
                            .information_refresh_time *
                        MILLISECONDS_IN_SECONDS;
                }

                index = get_option_index(reply_packet, reply_check, INF_MAX_RT_OPTION_CODE);

                if (index != -1) {
                    inf_max_rt =
                        reply_message->option_list[index]
                            .INF_MAX_RT_t
                            .INF_MAX_RT_value *
                        MILLISECONDS_IN_SECONDS;
                }

                usleep(refresh_time * MICROSECONDS_IN_MILLISECONDS);
                goto restartStateless;
            } else {
                waitToRetransmit(retrans_time * MICROSECONDS_IN_MILLISECONDS);

                if (elapse_time < 655350) {
                    sendInformationRequest(firstInfoReq, sockfd, ifname, elapse_time / 10);
                } else {
                    sendInformationRequest(firstInfoReq, sockfd, ifname, 65535);
                }

                retransmissionInfoReq++;
            }
        }
    }
}
