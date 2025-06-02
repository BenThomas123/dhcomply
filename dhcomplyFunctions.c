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
    const uint16_t oro_codes[ORO_ARRAY_LENGTH] = {
        USER_CLASS_OPTION_CODE, VENDOR_CLASS_OPTION_CODE, VENDOR_OPTS_OPTION_CODE,
        DNS_SERVERS_OPTION_CODE, DOMAIN_SEARCH_LIST_OPTION_CODE,
        INFORMATION_REFRESH_OPTION_CODE, FQDN_OPTION_CODE,
        PD_EXCLUDE_OPTION_CODE, SOL_MAX_RT_OPTION_CODE
    };

    while (fgets(buffer, sizeof(buffer), cfp)) {
        trim(buffer);

        if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_RENEW, buffer))
            config_file->reconfigure = 5;
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_REBIND, buffer))
            config_file->reconfigure = 6;
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, buffer))
            config_file->reconfigure = 7;
        else if (!strcmp(RAPID_COMMIT_LINE, buffer))
            config_file->rapid_commit = true;
        else if (strstr(buffer, OPTION_REQUEST_OPTION_LINE)) {
            char *option_string = substring(buffer, strlen(OPTION_REQUEST_OPTION_LINE), strlen(buffer));
            for (int option = 0; option < ORO_ARRAY_LENGTH; option++) {
                char expected_line[256];
                snprintf(expected_line, sizeof(expected_line), "%s%s", OPTION_REQUEST_OPTION_LINE, ORO[option]);
                if (!strcmp(option_string, ORO[option]) && !strcmp(expected_line, buffer)) {
                    config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                    valid_memory_allocation(config_file->oro_list);
                    config_file->oro_list[config_file->oro_list_length++] = oro_codes[option];
                    break;
                }
            }
            free(option_string);
        }
    }

    fclose(cfp);

    if (!strcmp(iaString, "NP")) {
        config_file->na = true;
        config_file->pd = true;
    } else if (!strcmp(iaString, "P")) {
        config_file->pd = true;
    } else if (!strcmp(iaString, "N")) {
        config_file->na = true;
    }

    return config_file;
}

int sendSolicit(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint16_t elapsed_time)
{
    if (!message || sockfd < 0) return -1;

    uint8_t buffer[9500];
    size_t offset = 0;

    // Header
    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> 16) & 0xFF;
    buffer[offset++] = (message->transaction_id >> 8) & 0xFF;
    buffer[offset++] = message->transaction_id & 0xFF;

    buffer[offset++] = (message->option_list[0].option_code >> 8) & 0xFF;
    buffer[offset++] =  message->option_list[0].option_code & 0xFF;

    buffer[offset++] = (message->option_list[0].option_length >> 8) & 0xFF;
    buffer[offset++] =  message->option_list[0].option_length & 0xFF;

    buffer[offset++] = (message->option_list[0].client_id_t.duid >> 16) & 0xFF;
    buffer[offset++] = (message->option_list[0].client_id_t.duid >> 8) & 0xFF;
    buffer[offset++] =  message->option_list[0].client_id_t.duid & 0xFF;

    buffer[offset++] = 0;
    buffer[offset++] = 8;
    buffer[offset++] = 0;
    buffer[offset++] = 2;

    buffer[offset++] = (elapsed_time >> 8) & 0xFF;
    buffer[offset++] = (elapsed_time) & 0xFF;

    /*for (size_t i = 0; ; i++) {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0 && opt->option_length == 0) break; // end

        if (offset + 4 + opt->option_length > sizeof(buffer)) return -1;

        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                memcpy(&buffer[offset], &opt->client_id_t.duid, sizeof(uint32_t));
                offset += sizeof(uint32_t);
                break;

            case ELAPSED_TIME_OPTION_CODE:
                buffer[offset++] = (opt->elapsed_time_t.elapsed_time_value >> 8) & 0xFF;
                buffer[offset++] = opt->elapsed_time_t.elapsed_time_value & 0xFF;
                break;

            case ORO_OPTION_CODE:
                memcpy(&buffer[offset], opt->option_request_t.option_request, opt->option_length);
                offset += opt->option_length;
                break;

            case IA_NA_OPTION_CODE:
                memcpy(&buffer[offset], &opt->ia_na_t.iaid, sizeof(uint32_t) * 3);
                offset += sizeof(uint32_t) * 3;
                break;

            case IA_PD_OPTION_CODE:
                memcpy(&buffer[offset], &opt->ia_pd_t.iaid, sizeof(uint32_t) * 3);
                offset += sizeof(uint32_t) * 3;
                break;

            default:
                // Unknown option: just skip content
                offset += opt->option_length;
                break;
        }
    }*/

    struct sockaddr_in6 src = {0};
    src.sin6_family = AF_INET6;
    src.sin6_port = htons(DHCP_CLIENT_PORT);
    src.sin6_addr = in6addr_any;
    bind(sockfd, (struct sockaddr*)&src, sizeof(src));

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }

    printf("Sent %zd bytes (Solicit)\n", sent);
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
    msg->transaction_id = rand() & 0xFFFFFF;

    msg->option_list = calloc(option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(msg->option_list);

    size_t index = 0;

    duid_ll_t *duid = (duid_ll_t *)malloc(sizeof(duid_ll_t));
    duid->duid_type = 3;
    duid->hw_type = 1;
    uint8_t mac[6];
    get_mac_address(ifname, mac);
    duid->mac = mac;

    // CLIENT_ID
    msg->option_list[index].option_code = CLIENT_ID_OPTION_CODE;
    msg->option_list[index].option_length = 4;
    msg->option_list[index].client_id_t.duid = rand() & 0xFFF;
    index++;

    // ELAPSED_TIME
    msg->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    msg->option_list[index].option_length = 2;
    msg->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    // ORO
    if (config->oro_list_length > 0) {
        msg->option_list[index].option_code = ORO_OPTION_CODE;
        msg->option_list[index].option_length = config->oro_list_length * sizeof(uint16_t);
        msg->option_list[index].option_request_t.option_request =
            malloc(msg->option_list[index].option_length);
        valid_memory_allocation(msg->option_list[index].option_request_t.option_request);
        memcpy(msg->option_list[index].option_request_t.option_request,
               config->oro_list, msg->option_list[index].option_length);
        index++;
    }

    // RAPID_COMMIT
    if (config->rapid_commit) {
        msg->option_list[index].option_code = RAPID_COMMIT_OPTION_CODE;
        msg->option_list[index++].option_length = 0;
    }

    // RECONF_ACCEPT
    if (config->reconfigure) {
        msg->option_list[index].option_code = RECONF_ACCEPT_OPTION_CODE;
        msg->option_list[index++].option_length = 0;
    }

    // IA_NA
    if (config->na) {
        msg->option_list[index].option_code = IA_NA_OPTION_CODE;
        msg->option_list[index].option_length = sizeof(uint32_t) * 3;
        msg->option_list[index].ia_na_t.iaid = rand();
        msg->option_list[index].ia_na_t.t1 = 0;
        msg->option_list[index].ia_na_t.t2 = 0;
        index++;
    } 

    // IA_PD
    if (config->pd) {
        msg->option_list[index].option_code = IA_PD_OPTION_CODE;
        msg->option_list[index].option_length = sizeof(uint32_t) * 3;
        msg->option_list[index].ia_pd_t.iaid = rand();
        msg->option_list[index].ia_pd_t.t1 = 0;
        msg->option_list[index].ia_pd_t.t2 = 0;
        index++;
    }

    return msg;
}

int get_mac_address(const char *iface_name, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}