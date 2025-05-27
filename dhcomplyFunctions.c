#include "dhcomplyFunctions.h"

config_t *read_config_file(char *iaString)
{

    config_t *config_file = (config_t *)malloc(sizeof(config_t));

    config_file->rapid_commit = false;
    config_file->reconfigure = 0;

    config_file->oro_list = NULL;
    config_file->oro_list_length = 0;

    FILE *cfp = fopen(CONFIG_FILE_PATH, "r");
    valid_file_pointer(cfp);
    char buffer[MAX_LINE_LEN];
    while (fgets(buffer, sizeof(buffer), cfp))
    {
        trim(buffer);
        if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_RENEW, buffer))
            config_file->reconfigure = 5;
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_REBIND, buffer))
            config_file->reconfigure = 6;
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, buffer))
            config_file->reconfigure = 7;

        if (!strcmp(RAPID_COMMIT_LINE, buffer))
            config_file->rapid_commit = true;

        if (strstr(buffer, OPTION_REQUEST_OPTION_LINE))
        {
            char option_string[] = substring(buffer, strlen(OPTION_REQUEST_OPTION_LINE) - 1,
                                             strlen(buffer) - strlen(OPTION_REQUEST_OPTION_LINE));
            for (int option = 0; option < ORO_ARRAY_LENGTH; option++)
            {
                if (!strcmp(option_string, ORO[option]) && !strcmp(strcat(OPTION_REQUEST_OPTION_LINE,
                                                                          ORO[option]),
                                                                   buffer))
                {
                    if (!strcmp(option_string, "user-class"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = USER_CLASS_OPTION_CODE;
                    }
                    else if (!strcmp(option_string, "vendor-class"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = VENDOR_CLASS_OPTION_CODE;
                    }
                    else if (!strcmp(option_string, "vendor-opts"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = VENDOR_OPTS_OPTION_CODE;
                    }
                    else if (!strcmp(option_string, "dns-servers"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = DNS_SERVERS_OPTION_CODE;
                    }
                    else if (!strcmp(option_string, "domain-search-list"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = DOMAIN_SEARCH_LIST_OPTION_CODE;
                    }
                    else if (!strcmp(option_string, "information-refresh-time"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = INFORM;
                    }
                    else if (!strcmp(option_string, "fqdn"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = 39;
                    }
                    else if (!strcmp(option_string, "pd-exclude"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = 67;
                    }
                    else if (!strcmp(option_string, "sol-max-rt"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = 82;
                    }
                    else if (!strcmp(option_string, "inf-max-rt"))
                    {
                        config_file->oro_list = realloc(config_file->oro_list, (config_file->oro_list_length + 1) * sizeof(uint16_t));
                        valid_memory_allocation(config_file->oro_list);
                        config_file->oro_list[config_file->oro_list_length++] = 83;
                    }
                    else
                    {
                        fprintf(stderr, "err: %s not a valid Option to request. it will not appear in the solicit or information request\n", option_string);
                    }
                    break;
                }
            }
        }
    }

    strcpy(iaString, to_uppercase(iaString));

    if (!strcmp(iaString, "NP"))
    {
        config_file->na = true;
        config_file->pd = true;
    }
    else
    {
        if (!strcmp(iaString, "P"))
        {
            config_file->pd = true;
        }
        else if (!strcmp(iaString, "N"))
        {
            config_file->na = true;
        }
    }

    return config_file;
}

int sendSolicit(dhcpv6_message_t *message, int sockfd)
{
    if (!message || sockfd < 0)
        return -1;

    uint8_t buffer[1500]; // safely large
    size_t offset = 0;

    buffer[offset++] = message->message_type;
    buffer[offset++] = (message->transaction_id >> 16) & 0xFF;
    buffer[offset++] = (message->transaction_id >> 8) & 0xFF;
    buffer[offset++] = message->transaction_id & 0xFF;

    for (int i = 0; i < 10; i++)
    {
        dhcpv6_option_t *opt = &message->option_list[i];
        if (opt->option_code == 0)
            continue;

        buffer[offset++] = (opt->option_code >> 8) & 0xFF;
        buffer[offset++] = opt->option_code & 0xFF;
        buffer[offset++] = (opt->option_length >> 8) & 0xFF;
        buffer[offset++] = opt->option_length & 0xFF;

        switch (opt->option_code)
        {
        case CLIENT_ID_OPTION_CODE:
            memcpy(&buffer[offset], &opt->client_id_t.duid, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            break;
        case ELAPSED_TIME_OPTION_CODE:
            buffer[offset++] = (opt->elapsed_time_t.elapsed_time_value >> 8) & 0xFF;
            buffer[offset++] = opt->elapsed_time_t.elapsed_time_value & 0xFF;
            break;
        case ORO_OPTION_CODE:
            memcpy(&buffer[offset], opt->option_request.option_request, opt->option_length);
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
            // rapid commit, reconf accept: no payload
            break;
        }
    }

    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCP_CLIENT_PORT);
    inet_pton(AF_INET6, ALL_DHCP_RELAY_AGENTS_AND_SERVERS, &dest.sin6_addr);

    ssize_t sent = sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0)
    {
        perror("sendto");
        return -1;
    }

    return 0;
}

dhcpv6_message_t *buildSolicit(config_t *config)
{
    dhcpv6_message_t *msg = malloc(sizeof(dhcpv6_message_t));
    if (!msg)
        return NULL;

    msg->message_type = SOLICIT_MESSAGE_TYPE;
    msg->transaction_id = rand() & 0xFFFFFF;

    size_t option_count = 2; // client ID + elapsed time
    if (config->oro_list_length > 0)
        option_count++;
    if (config->rapid_commit)
        option_count++;
    if (config->reconfigure)
        option_count++;
    if (config->na)
        option_count++;
    if (config->pd)
        option_count++;

    msg->option_list = calloc(option_count, sizeof(dhcpv6_option_t));
    if (!msg->option_list)
    {
        free(msg);
        return NULL;
    }

    size_t index = 0;

    // Client ID
    dhcpv6_option_t *client_id = &msg->option_list[index++];
    client_id->option_code = CLIENT_ID_OPTION_CODE;
    client_id->option_length = sizeof(uint32_t);
    client_id->client_id_t.duid = rand();

    // Elapsed Time
    dhcpv6_option_t *elapsed = &msg->option_list[index++];
    elapsed->option_code = ELAPSED_TIME_OPTION_CODE;
    elapsed->option_length = sizeof(uint16_t);
    elapsed->elapsed_time_t.elapsed_time_value = 0;

    // ORO
    if (config->oro_list_length > 0)
    {
        dhcpv6_option_t *oro = &msg->option_list[index++];
        oro->option_code = ORO_OPTION_CODE;
        oro->option_length = config->oro_list_length * sizeof(uint16_t);
        oro->option_request.option_request = malloc(oro->option_length);
        if (!oro->option_request.option_request)
        {
            free(msg->option_list);
            free(msg);
            return NULL;
        }
        memcpy(oro->option_request.option_request, config->oro_list, oro->option_length);
    }

    // Rapid Commit
    if (config->rapid_commit)
    {
        dhcpv6_option_t *rapid = &msg->option_list[index++];
        rapid->option_code = RAPID_COMMIT_OPTION_CODE;
        rapid->option_length = 0;
    }

    // Reconfigure Accept
    if (config->reconfigure)
    {
        dhcpv6_option_t *reconf = &msg->option_list[index++];
        reconf->option_code = RECONF_ACCEPT_OPTION_CODE;
        reconf->option_length = 0;
    }

    // IA_NA
    if (config->na)
    {
        dhcpv6_option_t *ia_na = &msg->option_list[index++];
        ia_na->option_code = IA_NA_OPTION_CODE;
        ia_na->option_length = sizeof(uint32_t) * 3;
        ia_na->iaid = rand();
        ia_na->t1 = 0;
        ia_na->t2 = 0;
        ia_na->ia_address = NULL;
    }

    // IA_PD
    if (config->pd)
    {
        dhcpv6_option_t *ia_pd = &msg->option_list[index++];
        ia_pd->option_code = IA_PD_OPTION_CODE;
        ia_pd->option_length = sizeof(uint32_t) * 3;
        ia_pd->iaid = rand();
        ia_pd->t1 = 0;
        ia_pd->t2 = 0;
        ia_pd->ia_prefix = NULL;
    }

    return msg;
}


