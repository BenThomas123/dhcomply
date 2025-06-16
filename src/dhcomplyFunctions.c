#include "dhcomplyFunctions.h"

config_t *read_config_file(char *iaString)
{
    config_t *config_file = malloc(sizeof(config_t));
    valid_memory_allocation(config_file);

    config_file->rapid_commit = false;
    config_file->reconfigure = 0;
    config_file->oro_list = NULL;
    config_file->oro_list_length = 0;
    config_file->na = false;
    config_file->pd = false;

    FILE *cfp = fopen(CONFIG_FILE_PATH, "r");
    valid_file_pointer(cfp);

    char buffer[MAX_LINE_LEN];
    config_file->oro_list = (uint8_t *)calloc(10, sizeof(uint8_t));
    valid_memory_allocation(config_file->oro_list);

    while (fgets(buffer, sizeof(buffer), cfp)) {
        trim(buffer);

        if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_RENEW, buffer)) {
            config_file->reconfigure = 5;
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_REBIND, buffer)) {
            config_file->reconfigure = 6;            
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, buffer)) {
            config_file->reconfigure = 7;
        }
        else if (!strcmp(RAPID_COMMIT_LINE, buffer)) {
            config_file->rapid_commit = true;
        }

        for (int i = 0; i < ORO_ARRAY_LENGTH; i++) {
            if (!strcmp(buffer, ORO[i])) {
                config_file->oro_list[config_file->oro_list_length++] = ORO_code[i];
            }
        }
    }

    fclose(cfp);

    if (!strcmp(iaString, "NP")) {
        config_file->na = true;
        config_file->pd = true;
    } else if (!strcmp(iaString, "P")) {
        config_file->pd = true;
        config_file->na = false;
    } else if (!strcmp(iaString, "N")) {
        config_file->na = true;
        config_file->pd = false;
    }

    return config_file;
}

int sendSolicit(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time)
{
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint8_t offset = 0;

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
                buffer[offset++] = (elapsed_time >> 8) & 0xFF;
                buffer[offset++] = elapsed_time & 0xFF;
                break;

            case ORO_OPTION_CODE:
                // Ensure ORO is present and valid
                for (int byte = 0; byte < opt->option_length / 2; byte++) {
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
    valid_socket(sent);

    return 0;
}

dhcpv6_message_t *buildSolicit(config_t *config, const char *ifname) {
    size_t option_count = 2;

    if (config->oro_list_length > 0) option_count++;
    if (config->rapid_commit) option_count++;
    if (config->reconfigure) option_count++;
    if (config->na) option_count++;
    if (config->pd) option_count++;

    dhcpv6_message_t *msg = malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(msg);

    msg->message_type = SOLICIT_MESSAGE_TYPE;
    msg->transaction_id = rand() & THREE_BYTE_MASK;

    msg->option_list = calloc(option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(msg->option_list);

    size_t index = 0;

    // CLIENT_ID
    msg->option_list[index].option_code = CLIENT_ID_OPTION_CODE;
    msg->option_list[index].option_length = 10;
    msg->option_list[index].client_id_t.duid.hw_type = 1;
    msg->option_list[index].client_id_t.duid.duid_type = 3;
    uint8_t *mac = (uint8_t *)calloc(MAC_ADDRESS_LENGTH, sizeof(uint8_t));
    valid_memory_allocation(mac);
    get_mac_address(ifname, mac);
    msg->option_list[index].client_id_t.duid.mac = (uint8_t *)calloc(MAC_ADDRESS_LENGTH, sizeof(uint8_t));
    for (int i = 0; i < MAC_ADDRESS_LENGTH; i++) {
        msg->option_list[index].client_id_t.duid.mac[i] = mac[i];
    }
    index++;

    // ELAPSED_TIME
    msg->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    msg->option_list[index].option_length = 2;
    msg->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    // ORO
    if (config->oro_list_length > 0) {
        msg->option_list[index].option_code = ORO_OPTION_CODE;
        msg->option_list[index].option_length = config->oro_list_length * 2;
        msg->option_list[index].option_request_t.option_request = (uint8_t *)malloc(msg->option_list[index].option_length);
        valid_memory_allocation(msg->option_list[index].option_request_t.option_request);
        memcpy(msg->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    // RAPID_COMMIT
    if (config->rapid_commit) {
        msg->option_list[index].option_code = RAPID_COMMIT_OPTION_CODE;
        msg->option_list[index].option_length = 0;
        index++;
    }

    // RECONF_ACCEPT
    if (config->reconfigure) {
        msg->option_list[index].option_code = RECONF_ACCEPT_OPTION_CODE;
        msg->option_list[index].option_length = 0;
        index++;
    }

    // IA_NA
    if (config->na) {
        msg->option_list[index].option_code = IA_NA_OPTION_CODE;
        msg->option_list[index].option_length = 12;
        msg->option_list[index].ia_na_t.iaid = rand() & FOUR_BYTE_MASK;
        msg->option_list[index].ia_na_t.t1 = 0;
        msg->option_list[index].ia_na_t.t2 = 0;
        index++;
    } 

    // IA_PD
    if (config->pd) {
        msg->option_list[index].option_code = IA_PD_OPTION_CODE;
        msg->option_list[index].option_length = 12;
        msg->option_list[index].ia_pd_t.iaid = rand() & FOUR_BYTE_MASK;
        msg->option_list[index].ia_pd_t.t1 = 0;
        msg->option_list[index].ia_pd_t.t2 = 0;
        index++;
    }

    msg->option_count = option_count;

    return msg;
}

int sendRequest(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time)
{
    if (!message || sockfd < 0) exit(-1);

    uint8_t buffer[MAX_PACKET_SIZE];
    uint8_t offset = 0;

    // Header
    buffer[offset++] = REQUEST_MESSAGE_TYPE;
    buffer[offset++] = (message->transaction_id >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = (message->transaction_id >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
    buffer[offset++] = message->transaction_id & ONE_BYTE_MASK;

    for (int i = 0; i < message->option_count; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) continue; // end

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

            case SERVER_ID_OPTION_CODE:
                //fprintf(stderr, "S: here\n");
                buffer[offset++] = (opt->server_id_t.duid.duid_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->client_id_t.duid.duid_type & ONE_BYTE_MASK;

                buffer[offset++] = (opt->server_id_t.duid.hw_type >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->server_id_t.duid.hw_type & ONE_BYTE_MASK;

                for (int octet = 0; octet < opt->option_length - 4; octet++) {
                    buffer[offset++] = opt->server_id_t.duid.mac[octet];
                }
                
                break;

            case IA_NA_OPTION_CODE:
                buffer[offset++] = (opt->ia_na_t.iaid >> THREE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.iaid >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.iaid >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_na_t.iaid & ONE_BYTE_MASK;

                buffer[offset++] = (opt->ia_na_t.t1 >> THREE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.t1 >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.t1 >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_na_t.t1 & ONE_BYTE_MASK;

                buffer[offset++] = (opt->ia_na_t.t2 >> THREE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.t2 >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_na_t.t2 >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_na_t.t2 & ONE_BYTE_MASK;
                
                break;

            case IA_ADDR_OPTION_CODE:
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 120) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 112) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 104) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 96) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 88) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 80) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 72) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 64) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 56) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 48) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 40) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 32) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 24) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 16) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.ipv6_address >> 8) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_address_t.ipv6_address & ONE_BYTE_MASK;

                buffer[offset++] = (opt->ia_address_t.prefered_lifetime >> THREE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.prefered_lifetime >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.prefered_lifetime >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_address_t.prefered_lifetime & ONE_BYTE_MASK;

                buffer[offset++] = (opt->ia_address_t.valid_lifetime >> THREE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.valid_lifetime >> TWO_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = (opt->ia_address_t.valid_lifetime >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = opt->ia_address_t.valid_lifetime & ONE_BYTE_MASK;

                break;
            case ELAPSED_TIME_OPTION_CODE:
                
                buffer[offset++] = (elapsed_time >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                buffer[offset++] = elapsed_time & ONE_BYTE_MASK;
                break;

            case ORO_OPTION_CODE:
                for (int byte = 0; byte < opt->option_length / 2; byte++) {
                    buffer[offset++] = (opt->option_request_t.option_request[byte] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                    buffer[offset++] = opt->option_request_t.option_request[byte] & ONE_BYTE_MASK;
                }

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
    valid_socket(sent);

    return 0;
}

bool check_for_message(int sockfd, uint8_t *packet, int type) {
    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ready = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready > 0 && FD_ISSET(sockfd, &read_fds)) {
        uint8_t buffer[MAX_PACKET_SIZE];
        ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
        memcpy(packet, buffer, MAX_PACKET_SIZE);
        if (len > 0 && buffer[0] == type) {
            return true;
        }
    }

    return false;
}

dhcpv6_message_t *parseAdvertisement(uint8_t *packet, dhcpv6_message_t *solicit) {

    dhcpv6_message_t *advertise_message = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));

    uint32_t id = 0;

    id = packet[1] << 16;
    id |= packet[2] << 8;
    id |= packet[3];

    if (id != solicit->transaction_id) {
        return NULL;
    }

    advertise_message->message_type = ADVERTISE_MESSAGE_TYPE;
    advertise_message->transaction_id = id;
    advertise_message->option_count = solicit->option_count - 1;

    advertise_message->option_list = (dhcpv6_option_t *)calloc(advertise_message->option_count, sizeof(dhcpv6_option_t));

    int index = 4;
    int option_index = 0;
    for (int i = 0; i < advertise_message->option_count; i++) {
        uint16_t option_code = advertise_message->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];
        uint16_t option_length = advertise_message->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];
        advertise_message->option_list[option_index].option_code = option_code;
        advertise_message->option_list[option_index].option_length = option_length;
        switch (option_code) {
            case SERVER_ID_OPTION_CODE:
                advertise_message->option_list[option_index].server_id_t.duid.hw_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].server_id_t.duid.hw_type = packet[index + 5] & ONE_BYTE_MASK;

                advertise_message->option_list[option_index].server_id_t.duid.duid_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].server_id_t.duid.duid_type = packet[index + 7] & ONE_BYTE_MASK;
                
                advertise_message->option_list[option_index].server_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                for (int x = 0; x < option_length; x++) {
                    advertise_message->option_list[option_index].server_id_t.duid.mac[x] = packet[index + (x + 8)];
                }

                break;
            case CLIENT_ID_OPTION_CODE:
               advertise_message->option_list[option_index].client_id_t.duid = solicit->option_list[option_index].client_id_t.duid;
                break;
            case IA_NA_OPTION_CODE:
                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_na_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_na_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_na_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }

                option_index++;
                advertise_message->option_list[option_index].option_code = 5;
                advertise_message->option_list[option_index].option_length = 24;

                uint128_t address = 0;
                
                for (int byte = 15; byte > -1; byte--) {
                    address <<= ONE_BYTE_SHIFT;
                    address |= packet[index + 20 + (15 - byte)];
                }

                advertise_message->option_list[option_index].ia_address_t.ipv6_address = address;

                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_address_t.prefered_lifetime |= (packet[index + (36 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_address_t.valid_lifetime |= (packet[index + (40 + byte)] << (8 * (3 - byte)));
                }

                break;
            case IA_PD_OPTION_CODE:
                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_pd_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_pd_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_pd_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }
                break;
            case RECONF_ACCEPT_OPTION_CODE:
                break;
            case DNS_SERVERS_OPTION_CODE:

                break;
            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                break;
            default:
                break;
        }
        option_index++;
        index += (option_length + 4);
    }
    advertise_message->option_count = option_index - 1;
    return advertise_message;
}

dhcpv6_message_t * buildRequest(dhcpv6_message_t *advertisement, config_t *config) {
    uint8_t option_count = advertisement->option_count;

   dhcpv6_message_t *request = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
   valid_memory_allocation(request);

    request->message_type = REQUEST_MESSAGE_TYPE;
    request->transaction_id = rand() & THREE_BYTE_MASK;

    request->option_list = calloc(option_count + 2, sizeof(dhcpv6_option_t));
    valid_memory_allocation(request->option_list);

    size_t index = 0;
    for (uint8_t i = 0; i < option_count; i++) {
        dhcpv6_option_t *opt = &advertisement->option_list[i];
        uint16_t option_code = opt->option_code;
        uint16_t option_length = opt->option_length;
        //if (option_code < 1 || option_code > 90) continue;
        request->option_list[index].option_code = option_code;
        request->option_list[index].option_length = option_length;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                request->option_list[index].client_id_t = advertisement->option_list[i].client_id_t;
                break;

            case SERVER_ID_OPTION_CODE:
                request->option_list[index].server_id_t = advertisement->option_list[i].server_id_t;
                break;

            case IA_NA_OPTION_CODE:
                request->option_list[index].ia_na_t = advertisement->option_list[i].ia_na_t;
                break;

            case IA_ADDR_OPTION_CODE:
                request->option_list[index].ia_address_t = advertisement->option_list[i].ia_address_t;
                break;

            case IA_PD_OPTION_CODE:
                request->option_list[index].ia_pd_t = advertisement->option_list[i].ia_pd_t;
                break;

            default:
                break;
        }

        index++;
    }

    request->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    request->option_list[index].option_length = 2;
    request->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    if (config->oro_list_length > 0) {
        request->option_list[index].option_code = ORO_OPTION_CODE;
        request->option_list[index].option_length = config->oro_list_length * 2;
        request->option_list[index].option_request_t.option_request = (uint8_t *)calloc(request->option_list[index].option_length / 2, sizeof(uint8_t));
        valid_memory_allocation(request->option_list[index].option_request_t.option_request);
        memcpy(request->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    request->option_count = index;

    return request;
}

int parseReply(uint8_t *packet, dhcpv6_message_t *request, const char *iface) {
    uint32_t id = 0;

    id = packet[1] << 16;
    id |= packet[2] << 8;
    id |= packet[3];

    if (id != request->transaction_id) {
        return -1;
    }

    request->option_count = request->option_count - 1;

    request->option_list = (dhcpv6_option_t *)calloc(request->option_count, sizeof(dhcpv6_option_t));

    int index = 4;
    int option_index = 0;
    for (int i = 0; i < request->option_count; i++) {
        uint16_t option_code = request->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];
        uint16_t option_length = request->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];
        request->option_list[option_index].option_code = option_code;
        request->option_list[option_index].option_length = option_length;
        switch (option_code) {
            case IA_NA_OPTION_CODE:
                for (int byte = 3; byte > -1; byte--) {
                    request->option_list[option_index].ia_na_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    request->option_list[option_index].ia_na_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    request->option_list[option_index].ia_na_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }

                option_index++;
                request->option_list[option_index].option_code = 5;
                request->option_list[option_index].option_length = 24;

                uint128_t address = 0;
                
                for (int byte = 15; byte > -1; byte--) {
                    address <<= ONE_BYTE_SHIFT;
                    address |= packet[index + 20 + (15 - byte)];
                }

                request->option_list[option_index].ia_address_t.ipv6_address = address;

                for (int byte = 3; byte > -1; byte--) {
                    request->option_list[option_index].ia_address_t.prefered_lifetime |= (packet[index + (36 + byte)] << (8 * (3 - byte)));
                    request->option_list[option_index].ia_address_t.valid_lifetime |= (packet[index + (40 + byte)] << (8 * (3 - byte)));
                }

                char cmd[512];
                char address_string[39];
                uint128_to_str(address, address_string);
                int a = sprintf(cmd, "sudo ip -6 addr %s/%d dev %s preferred_lft %lu valid_lft %lu", address_string, 128, iface, request->option_list[option_index].ia_address_t.prefered_lifetime, request->option_list[option_index].ia_address_t.valid_lifetime);
                system(cmd);
                fprintf(stderr, "%d\n", a);

                break;
            case IA_PD_OPTION_CODE:
                for (int byte = 3; byte > -1; byte--) {
                    request->option_list[option_index].ia_pd_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    request->option_list[option_index].ia_pd_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    request->option_list[option_index].ia_pd_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }
                break;
            default:
                break;
        }
        option_index++;
        index += (option_length + 4);
    }
    request->option_count = option_index - 1;
    return 0;
}

int get_mac_address(const char *iface_name, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    valid_socket(sock);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        exit(-1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_ADDRESS_LENGTH);
    close(sock);
    return 0;
}
