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
    memcpy(msg->option_list[index].client_id_t.duid.mac, mac, MAC_ADDRESS_LENGTH);

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

    return msg;
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
