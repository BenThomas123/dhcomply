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

int sendSolicit(dhcpv6_message_t *message, int sockfd, const char *iface_name)
{
    if (!message || sockfd < 0) return -1;

    uint8_t buffer[1500];
    size_t offset = 0;

    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> 16) & 0xFF;
    buffer[offset++] = (message->transaction_id >> 8) & 0xFF;
    buffer[offset++] = message->transaction_id & 0xFF;

    for (size_t i = 0; i < message->option_count; i++) {
        const dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0) continue;

        if (offset + 4 + opt->option_length >= sizeof(buffer)) return -1;

        buffer[offset++] = (opt->option_code >> 8) & 0xFF;
        buffer[offset++] = opt->option_code & 0xFF;
        buffer[offset++] = (opt->option_length >> 8) & 0xFF;
        buffer[offset++] = opt->option_length & 0xFF;

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
            case IA_PD_OPTION_CODE:
                memcpy(&buffer[offset], &opt->ia_na_t.iaid, sizeof(uint32_t) * 3);
                offset += sizeof(uint32_t) * 3;
                break;
            default:
                break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_SERVER_PORT);
    inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(iface_name); // required for link-local multicast

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }

    printf("Sent %zd bytes (Solicit)\n", sent);
    return 0;
}

dhcpv6_message_t *buildSolicit(config_t *config) {
    dhcpv6_message_t *msg = malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(msg);

    msg->message_type = SOLICIT_MESSAGE_TYPE;
    msg->transaction_id = rand() & 0xFFFFFF;

    msg->option_count = 2; // CLIENTID + ELAPSED_TIME

    if (config->oro_list_length > 0) msg->option_count++;
    if (config->rapid_commit) msg->option_count++;
    if (config->reconfigure) msg->option_count++;
    if (config->na) msg->option_count++;
    if (config->pd) msg->option_count++;

    msg->option_list = calloc(msg->option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(msg->option_list);

    size_t index = 0;

    // CLIENT_ID
    msg->option_list[index].option_code = CLIENT_ID_OPTION_CODE;
    msg->option_list[index].option_length = sizeof(uint32_t);
    msg->option_list[index++].client_id_t.duid = rand(); // Simplified DUID

    // ELAPSED_TIME
    msg->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    msg->option_list[index].option_length = sizeof(uint16_t);
    msg->option_list[index++].elapsed_time_t.elapsed_time_value = 0;

    // ORO (Option Request Option)
    if (config->oro_list_length > 0) {
        dhcpv6_option_t *oro = &msg->option_list[index++];
        oro->option_code = ORO_OPTION_CODE;
        oro->option_length = config->oro_list_length * sizeof(uint16_t);
        oro->option_request_t.option_request = malloc(oro->option_length);
        valid_memory_allocation(oro->option_request_t.option_request);
        memcpy(oro->option_request_t.option_request, config->oro_list, oro->option_length);
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
        dhcpv6_option_t *ia_na = &msg->option_list[index++];
        ia_na->option_code = IA_NA_OPTION_CODE;
        ia_na->option_length = sizeof(uint32_t) * 3;
        ia_na->ia_na_t.iaid = rand();
        ia_na->ia_na_t.t1 = 0;
        ia_na->ia_na_t.t2 = 0;
        ia_na->ia_na_t.addresses = NULL;
    }

    // IA_PD
    if (config->pd) {
        dhcpv6_option_t *ia_pd = &msg->option_list[index++];
        ia_pd->option_code = IA_PD_OPTION_CODE;
        ia_pd->option_length = sizeof(uint32_t) * 3;
        ia_pd->ia_pd_t.iaid = rand();
        ia_pd->ia_pd_t.t1 = 0;
        ia_pd->ia_pd_t.t2 = 0;
        ia_pd->ia_pd_t.prefixes = NULL;
    }

    return msg;
} 

