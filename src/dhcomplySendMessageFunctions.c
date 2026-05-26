#include "dhcomplySendMessageFunctions.h"

int sendSolicit(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (size_t i = 0; message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) break; // end

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;

        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int i = 0; i < MAC_ADDRESS_LENGTH; i++)
                    buffer[offset++] = opt->client_id_t.duid.mac[i] & ONE_BYTE_MASK;

                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }

                break;

            case IA_NA_OPTION_CODE:
                int offset_na_2 = offset + 4;
                int offset_na_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_na_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_2++] = (opt->ia_na_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_3++] = (opt->ia_na_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_na_3;
                break;

            case IA_PD_OPTION_CODE:
                int offset_pd_2 = offset + 4;
                int offset_pd_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_pd_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_2++] = (opt->ia_pd_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_3++] = (opt->ia_pd_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_pd_3;
                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 src = {0};
    src.sin6_family = AF_INET6;
    src.sin6_port = htons(DHCP_CLIENT_PORT);
    src.sin6_addr = in6addr_any;
    bind(sockfd, (struct sockaddr*)&src, sizeof(src));

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
	packet_sent_sucessfully(sent);

    return 0;
}

int sendRequest(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    // Header
    buffer[offset++] = REQUEST_MESSAGE_TYPE;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (int i = 0; i < message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) continue;

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int index = 0; index < MAC_ADDRESS_LENGTH; index++)
                    buffer[offset++] = opt->client_id_t.duid.mac[index] & ONE_BYTE_MASK;

                break;

            case SERVER_ID_OPTION_CODE:
                buffer[offset++] = (opt->server_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->server_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int octet = 0; octet < opt->option_length - 4; octet++) {
                    buffer[offset++] = opt->server_id_t.duid.mac[octet];
                }

                break;

            case IA_NA_OPTION_CODE:
                int offset_na_2 = offset + 4;
                int offset_na_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_na_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_2++] = (opt->ia_na_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_3++] = (opt->ia_na_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_na_3;

                break;

            case IA_ADDR_OPTION_CODE:
                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_address_t.ipv6_address >> octet) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;

                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                break;

            case IA_PD_OPTION_CODE:
                int offset_pd_2 = offset + 4;
                int offset_pd_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_pd_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_2++] = (opt->ia_pd_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_3++] = (opt->ia_pd_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_pd_3;
                break;

            case IAPREFIX_OPTION_CODE:
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                buffer[offset++] = opt->ia_prefix_t.prefix_length;

                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_prefix_t.ipv6_prefix >> octet) & ONE_BYTE_MASK;
                }
                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }
                break;

            case DNS_SERVERS_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->dns_recursive_name_server_t.dns_servers[byte];
                }
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->domain_search_list_t.search_list[byte];
                }

                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    packet_sent_sucessfully(sent);

    return 0;
}

int sendRenew(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    // Header
    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (int i = 0; i < message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) continue;

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int index = 0; index < MAC_ADDRESS_LENGTH; index++) {
                    buffer[offset++] = opt->client_id_t.duid.mac[index] & ONE_BYTE_MASK;
                }

                break;

            case SERVER_ID_OPTION_CODE:
                buffer[offset++] = (opt->server_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->server_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int octet = 0; octet < opt->option_length - 4; octet++) {
                    buffer[offset++] = opt->server_id_t.duid.mac[octet];
                }

                break;

            case IA_NA_OPTION_CODE:
                int offset_na_2 = offset + 4;
                int offset_na_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_na_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_2++] = (opt->ia_na_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_3++] = (opt->ia_na_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_na_3;

                break;

            case IA_ADDR_OPTION_CODE:
                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_address_t.ipv6_address >> octet) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;

                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                break;

            case IA_PD_OPTION_CODE:
                int offset_pd_2 = offset + 4;
                int offset_pd_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_pd_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_2++] = (opt->ia_pd_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_3++] = (opt->ia_pd_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_pd_3;
                break;

            case IAPREFIX_OPTION_CODE:
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                buffer[offset++] = opt->ia_prefix_t.prefix_length;

                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_prefix_t.ipv6_prefix >> octet) & ONE_BYTE_MASK;
                }
                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }
                break;

            case DNS_SERVERS_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->dns_recursive_name_server_t.dns_servers[byte];
                }
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->domain_search_list_t.search_list[byte];
                }

                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    packet_sent_sucessfully(sent);

    return 0;
}

int sendRebind(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    // Header
    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (int i = 0; i < message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if ((opt->option_code == 0 && opt->option_length == 0) || opt->option_code == 2) continue;

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int index = 0; index < MAC_ADDRESS_LENGTH; index++) {
                    buffer[offset++] = opt->client_id_t.duid.mac[index] & ONE_BYTE_MASK;
                }

                break;

            case IA_NA_OPTION_CODE:
                int offset_na_2 = offset + 4;
                int offset_na_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_na_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_2++] = (opt->ia_na_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_3++] = (opt->ia_na_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_na_3;

                break;

            case IA_ADDR_OPTION_CODE:
                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_address_t.ipv6_address >> octet) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;

                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                break;

            case IA_PD_OPTION_CODE:
                int offset_pd_2 = offset + 4;
                int offset_pd_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_pd_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_2++] = (opt->ia_pd_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_pd_3++] = (opt->ia_pd_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_pd_3;
                break;

            case IAPREFIX_OPTION_CODE:
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_prefix_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                buffer[offset++] = opt->ia_prefix_t.prefix_length;

                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_prefix_t.ipv6_prefix >> octet) & ONE_BYTE_MASK;
                }
                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }
                break;

            case DNS_SERVERS_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->dns_recursive_name_server_t.dns_servers[byte];
                }
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->domain_search_list_t.search_list[byte];
                }

                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    packet_sent_sucessfully(sent);

    return 0;
}

int sendDecline(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    // Header
    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (int i = 0; i < message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) continue;

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int index = 0; index < MAC_ADDRESS_LENGTH; index++) {
                    buffer[offset++] = opt->client_id_t.duid.mac[index] & ONE_BYTE_MASK;
                }

                break;

            case SERVER_ID_OPTION_CODE:
                buffer[offset++] = (opt->server_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->server_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int octet = 0; octet < opt->option_length - 4; octet++) {
                    buffer[offset++] = opt->server_id_t.duid.mac[octet];
                }

                break;

            case IA_NA_OPTION_CODE:
                int offset_na_2 = offset + 4;
                int offset_na_3 = offset + 8;
                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_na_t.iaid >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_2++] = (opt->ia_na_t.t1 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    buffer[offset_na_3++] = (opt->ia_na_t.t2 >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }
                offset = offset_na_3;

                if (i + 1 < message->option_count &&
                    message->option_list[i + 1].option_code == IA_ADDR_OPTION_CODE) {
                    dhcpv6_option_t *address = &message->option_list[++i];

                    buffer[offset++] = (address->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = address->option_code & ONE_BYTE_MASK;
                    buffer[offset++] = (address->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = address->option_length & ONE_BYTE_MASK;

                    for (int octet = 120; octet > -1; octet -= 8) {
                        buffer[offset++] = (address->ia_address_t.ipv6_address >> octet) & ONE_BYTE_MASK;
                    }

                    for (int octet = 3; octet > -1; octet--) {
                        buffer[offset++] = (address->ia_address_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    }

                    for (int octet = 3; octet > -1; octet--) {
                        buffer[offset++] = (address->ia_address_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                    }
                }

                break;

            case IA_ADDR_OPTION_CODE:
                for (int octet = 120; octet > -1; octet -= 8) {
                    buffer[offset++] = (opt->ia_address_t.ipv6_address >> octet) & ONE_BYTE_MASK;
                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.preferred_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;

                }

                for (int octet = 3; octet > -1; octet--) {
                    buffer[offset++] = (opt->ia_address_t.valid_lifetime >> (ONE_BYTE_SHIFT * octet)) & ONE_BYTE_MASK;
                }

                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }
                break;

            case DNS_SERVERS_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->dns_recursive_name_server_t.dns_servers[byte];
                }
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length; byte++) {
                    buffer[offset++] = opt->domain_search_list_t.search_list[byte];
                }

                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    packet_sent_sucessfully(sent);

    return 0;
}

int sendInformationRequest(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t offset = 0;

    // Header
    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (size_t i = 0; message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) break; // end

        buffer[offset++] = (opt->option_code >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_code & ONE_BYTE_MASK;

        buffer[offset++] = (opt->option_length >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
        buffer[offset++] =  opt->option_length & ONE_BYTE_MASK;

        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                buffer[offset++] = (opt->client_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->client_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int i = 0; i < MAC_ADDRESS_LENGTH; i++)
                    buffer[offset++] = opt->client_id_t.duid.mac[i] & ONE_BYTE_MASK;

                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / OPTION_CODE_LENGTH_IN_ORO; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }

                break;

            default:
                break;
        }
    }

    struct sockaddr_in6 src = {0};
    src.sin6_family = AF_INET6;
    src.sin6_port = htons(DHCP_CLIENT_PORT);
    src.sin6_addr = in6addr_any;
    bind(sockfd, (struct sockaddr*)&src, sizeof(src));

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    packet_sent_sucessfully(sent);

    return 0;
}
