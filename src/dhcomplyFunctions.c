#include "dhcomplyFunctions.h"

config_t *read_config_file(char *iaString) {
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


    char line[MAX_LINE_LEN];


    config_file->oro_list = (uint8_t *)calloc(ORO_ARRAY_LENGTH, sizeof(uint8_t));
    valid_memory_allocation(config_file->oro_list);

    while (fgets(line, sizeof(line), cfp)) {
        trim(line);

        if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_RENEW, line)) {
            config_file->reconfigure = 5;
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_REBIND, line)) {
            config_file->reconfigure = 6;
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, line)) {
            config_file->reconfigure = 7;
        }
        else if (!strcmp(RAPID_COMMIT_LINE, line)) {
            config_file->rapid_commit = true;
        }

        for (int i = 0; i < ORO_ARRAY_LENGTH; i++) {
            if (!strcmp(line, ORO[i])) {
                config_file->oro_list[config_file->oro_list_length++] = ORO_code[i];
            }
        }
    }

    fclose(cfp);

    if (!strcmp(iaString, IA_BOTH_STRING)) {
        config_file->na = true;
        config_file->pd = true;
    } else if (!strcmp(iaString, IAPD_STRING)) {
        config_file->pd = true;
        config_file->na = false;
    } else if (!strcmp(iaString, IANA_STRING)) {
        config_file->na = true;
        config_file->pd = false;
    }

    return config_file;
}

uint32_t readIANA() {
    FILE *fp = fopen("/etc/dhcomplyIA.conf", "r");
    valid_file_pointer(fp);

	char IA[9];
	if (fgets(IA, sizeof(IA), fp)) {
    	size_t len = strlen(IA);
    	if (len > 0 && IA[len - 1] == '\n') {
        	IA[len - 1] = '\0';
    	}

    	uint32_t num = strtol(IA, NULL, 16);
		return num;
	}


    return 0;
}

uint32_t readIAPD() {
    FILE *fp = fopen("/etc/dhcomplyIA.conf", "r");
    valid_file_pointer(fp);

	char IA[9];
	fgets(IA, sizeof(IA), fp)
	if (fgets(IA, sizeof(IA), fp)) {
    	size_t len = strlen(IA);
    	if (len > 0 && IA[len - 1] == '\n') {
        	IA[len - 1] = '\0';
    	}

    	uint32_t num = strtol(IA, NULL, 16);
		return num;
	}


    return 0;
}

int check_for_message(int sockfd, uint8_t *packet, int type) {
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
        memcpy(packet, buffer, len);
        if (buffer[0] == type) {
            return len;
        }
    }

    return 0;
}

bool check_dad_failure(const char *interface) {
    char command[256];
    snprintf(command, sizeof(command), "./check_dad.sh %s", interface);
    int status = system(command);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 2) {
            return true;
        } else if (code == 0) {
            return false;
        }
    }

    return false;
}

uint32_t valid_transaction_id (uint8_t byte1, uint8_t byte2, uint8_t byte3) {
    uint32_t trans_id = 0;

    trans_id |= (byte1 << TWO_BYTE_SHIFT);
    trans_id |= (byte2 << ONE_BYTE_SHIFT);
    trans_id |= byte3;

    return trans_id;
}

uint8_t get_option_count(uint8_t *packet, unsigned long int size, uint8_t *iaoption_count) {
    long unsigned int index = 4;
    uint8_t option_count = 0;

    while (index < size) {
        uint16_t option_code = packet[index] << ONE_BYTE_SHIFT;
        option_code |= packet[index + 1];
        if (option_code == IA_NA_OPTION_CODE|| option_code == IA_PD_OPTION_CODE) {
            option_count++;
            (*iaoption_count)++;
        }
        uint16_t option_length = packet[index + 2] << ONE_BYTE_SHIFT;
        option_length |= packet[index + 3];
        option_count++;
        index += (option_length + 4);
    }

    return option_count;
}

int get_option_index(uint8_t *packet, unsigned long int size, uint8_t desired_option_code) {
    long unsigned int index = 4;
    uint8_t option_index = 0;

    while (index < size) {
        uint16_t option_code = packet[index] << ONE_BYTE_SHIFT;
        option_code |= packet[index + 1];
        if (option_code == desired_option_code) return option_index;
        uint16_t option_length = packet[index + 2] << ONE_BYTE_SHIFT;
        option_length |= packet[index + 3];
        index += (option_length + 4);
        option_index++;
    }

    return -1;
}

int writeLease(IANA_t *iana, IAPD_t *iapd, const char *iface_name) {
    cJSON *root = cJSON_CreateObject();
    cJSON *leases = cJSON_AddArrayToObject(root, "leases");

    if (iana) {
        cJSON *iana_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(iana_obj, "type", "IANA");
        char hexstring[11];
        sprintf(hexstring, "%08X", iana->iaid);
        cJSON_AddStringToObject(iana_obj, "iaid", hexstring);
        cJSON_AddNumberToObject(iana_obj, "t1", iana->t1);
        cJSON_AddNumberToObject(iana_obj, "t2", iana->t2);
        cJSON_AddStringToObject(iana_obj, "address", iana->address);
        cJSON_AddNumberToObject(iana_obj, "preferred_lifetime", iana->preferredlifetime);
        cJSON_AddNumberToObject(iana_obj, "valid_lifetime", iana->validlifetime);
        cJSON_AddItemToArray(leases, iana_obj);
    }

    if (iapd) {
        cJSON *iapd_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(iapd_obj, "type", "IAPD");
        char hexstring2[11];
        sprintf(hexstring2, "%08X", iapd->iaid);
        cJSON_AddStringToObject(iapd_obj, "iaid", hexstring2);
        cJSON_AddNumberToObject(iapd_obj, "t1", iapd->t1);
        cJSON_AddNumberToObject(iapd_obj, "t2", iapd->t2);
        cJSON_AddStringToObject(iapd_obj, "prefix", format_ipv6_prefix(iapd->prefix_length, iapd->prefix));
        cJSON_AddNumberToObject(iapd_obj, "prefix_length", iapd->prefix_length);
        cJSON_AddNumberToObject(iapd_obj, "preferred_lifetime", iapd->preferredlifetime);
        cJSON_AddNumberToObject(iapd_obj, "valid_lifetime", iapd->validlifetime);
        cJSON_AddItemToArray(leases, iapd_obj);
    }

    char *json_string = cJSON_Print(root);
    if (!json_string) {
        cJSON_Delete(root);
        return -1;
    }

    char filename[strlen(iface_name) + 35];
    snprintf(filename, sizeof(filename), "/var/lib/dhcp/lease_%s.json", iface_name);

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        free(json_string);
        cJSON_Delete(root);
        return -1;
    }
    fputs(json_string, f);
    fclose(f);

    free(json_string);
    cJSON_Delete(root);

    return 0;
}

uint8_t renewsAllowed(uint32_t t1minust2) {
    uint8_t index = 0;
    uint8_t elapsed_time = renew_upper[index] / MILLISECONDS_IN_SECONDS;
    while (elapsed_time < t1minust2) {
        index++;
        elapsed_time += (renew_upper[index] / MILLISECONDS_IN_SECONDS);
    } 

    return index;
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
    valid_memory_allocation(msg->option_list[index].client_id_t.duid.mac);
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
        msg->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
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
        msg->option_list[index].ia_na_t.iaid = readIANA();
        msg->option_list[index].ia_na_t.t1 = 0;
        msg->option_list[index].ia_na_t.t2 = 0;
        index++;
    } 

    // IA_PD
    if (config->pd) {
        msg->option_list[index].option_code = IA_PD_OPTION_CODE;
        msg->option_list[index].option_length = 12;
        msg->option_list[index].ia_pd_t.iaid = readIAPD();
        msg->option_list[index].ia_pd_t.t1 = 0;
        msg->option_list[index].ia_pd_t.t2 = 0;
        index++;
    }

    msg->option_count = option_count;

    return msg;
}

int sendSolicit(dhcpv6_message_t *message, int sockfd, const char *iface_name, uint32_t elapsed_time) {
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

dhcpv6_message_t *parseAdvertisement(uint8_t *packet, dhcpv6_message_t *solicit, int size) {

    dhcpv6_message_t *advertise_message = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(advertise_message);

    bool badAdvertisement = false;
    advertise_message->valid = true;
    if (valid_transaction_id(packet[1], packet[2], packet[3]) != solicit->transaction_id) {
        badAdvertisement = true;
    }

    uint8_t ia_option_count = 0;
    uint8_t option_count = get_option_count(packet, size, &ia_option_count);

    advertise_message->message_type = ADVERTISE_MESSAGE_TYPE;
    advertise_message->transaction_id = valid_transaction_id(packet[1], packet[2], packet[3]);
    advertise_message->option_count = option_count;

    advertise_message->option_list = (dhcpv6_option_t *)calloc(option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(advertise_message->option_list);

    int index = 4;
    int option_index = 0;

    int all_valid_options_included_counter = 0;
    for (int i = 0; i < option_count - ia_option_count; i++) {
        uint16_t option_code = advertise_message->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];
        uint16_t option_length = advertise_message->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];
        advertise_message->option_list[option_index].option_code = option_code;
        advertise_message->option_list[option_index].option_length = option_length;
        switch (option_code) {
            case STATUS_CODE_OPTION_CODE:
                uint8_t status_code = packet[index + 5];
                if (status_code) {
                    badAdvertisement = true;
                }

                break;
            case SERVER_ID_OPTION_CODE:
                all_valid_options_included_counter += SERVER_ID_OPTION_CODE;
                advertise_message->option_list[option_index].server_id_t.duid.hw_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].server_id_t.duid.hw_type = packet[index + 5] & ONE_BYTE_MASK;
                

                advertise_message->option_list[option_index].server_id_t.duid.duid_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].server_id_t.duid.duid_type = packet[index + 7] & ONE_BYTE_MASK;
                
                advertise_message->option_list[option_index].server_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(advertise_message->option_list[option_index].server_id_t.duid.mac);
                for (int x = 0; x < option_length; x++) {
                    advertise_message->option_list[option_index].server_id_t.duid.mac[x] = packet[index + (x + 8)];
                }

                break;
            case CLIENT_ID_OPTION_CODE:
                all_valid_options_included_counter += CLIENT_ID_OPTION_CODE;
                advertise_message->option_list[option_index].client_id_t.duid.duid_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].client_id_t.duid.duid_type = packet[index + 5] & ONE_BYTE_MASK;
                
                if (advertise_message->option_list[option_index].client_id_t.duid.duid_type != solicit->option_list[option_index].client_id_t.duid.duid_type) {
                    badAdvertisement = true;
                }

                advertise_message->option_list[option_index].client_id_t.duid.hw_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                advertise_message->option_list[option_index].client_id_t.duid.hw_type = packet[index + 7] & ONE_BYTE_MASK;
        
                if (advertise_message->option_list[option_index].client_id_t.duid.hw_type != solicit->option_list[option_index].client_id_t.duid.hw_type) {
                    badAdvertisement = true;
                }

                advertise_message->option_list[option_index].client_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(advertise_message->option_list[option_index].client_id_t.duid.mac);
                for (int x = 0; x < MAC_ADDRESS_LENGTH; x++) {
                    advertise_message->option_list[option_index].client_id_t.duid.mac[x] = packet[index + (x + 8)];
                    if (advertise_message->option_list[option_index].client_id_t.duid.mac[x] != solicit->option_list[option_index].client_id_t.duid.mac[x]) {
                        badAdvertisement = true;
                    }
                }

                break;
            case IA_NA_OPTION_CODE:
                all_valid_options_included_counter += IA_NA_OPTION_CODE;
                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_na_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_na_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    advertise_message->option_list[option_index].ia_na_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }

                option_index++;
                advertise_message->option_list[option_index].option_code |= (packet[index + 16] << ONE_BYTE_SHIFT);
                advertise_message->option_list[option_index].option_code |= packet[index + 17];
                if (advertise_message->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {
                    int status_code = 0;
                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);
                    status_code |= packet[index + 21];

                    if (status_code) {
                        badAdvertisement = true;
                    }
                }

                advertise_message->option_list[option_index].option_length |= (packet[index + 18] << ONE_BYTE_SHIFT);
                advertise_message->option_list[option_index].option_length |= packet[index + 19];

                uint128_t address = 0;
                
                for (int byte = START_POINT_IN_READING_ADDRESS; byte > -1; byte--) {
                    address <<= ONE_BYTE_SHIFT;
                    address |= packet[index + 20 + (START_POINT_IN_READING_ADDRESS - byte)];
                }

                all_valid_options_included_counter += IA_ADDR_OPTION_CODE;
                advertise_message->option_list[option_index].ia_address_t.ipv6_address = address;

                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_address_t.preferred_lifetime |= (packet[index + (36 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    advertise_message->option_list[option_index].ia_address_t.valid_lifetime |= (packet[index + (40 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                break;
            case IA_PD_OPTION_CODE:
                all_valid_options_included_counter += IA_PD_OPTION_CODE;
                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_pd_t.iaid |= (packet[index + (4 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    advertise_message->option_list[option_index].ia_pd_t.t1 |= (packet[index + (8 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    advertise_message->option_list[option_index].ia_pd_t.t2 |= (packet[index + (12 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                option_index++;
                advertise_message->option_list[option_index].option_code |= (packet[index + 16] << ONE_BYTE_SHIFT);
                advertise_message->option_list[option_index].option_code |= packet[index + 17];
                advertise_message->option_list[option_index].option_length |= (packet[index + 18] << ONE_BYTE_SHIFT);
                advertise_message->option_list[option_index].option_length |= packet[index + 19];

                if (advertise_message->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {
                    int status_code = 0;
                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);
                    status_code |= packet[index + 21];

                    if (status_code) {
                        badAdvertisement = true;
                    }
                }

                all_valid_options_included_counter += IAPREFIX_OPTION_CODE;

                for (int byte = 3; byte > -1; byte--) {
                    advertise_message->option_list[option_index].ia_prefix_t.preferred_lifetime |= (packet[index + (20 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    advertise_message->option_list[option_index].ia_prefix_t.valid_lifetime |= (packet[index + (24 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                advertise_message->option_list[option_index].ia_prefix_t.prefix_length = packet[index + 28];
                uint128_t prefix = 0;
                
                for (int byte = 15; byte > 0; byte--) {
                    prefix <<= ONE_BYTE_SHIFT;
                    prefix |= packet[index + 29 + (START_POINT_IN_READING_ADDRESS - byte)];
                }

                advertise_message->option_list[option_index].ia_prefix_t.ipv6_prefix = prefix;
                break;
            case RECONF_ACCEPT_OPTION_CODE:
                break;
            case DNS_SERVERS_OPTION_CODE:
                advertise_message->option_list[option_index].dns_recursive_name_server_t.dns_servers = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(advertise_message->option_list[option_index].dns_recursive_name_server_t.dns_servers);
                for (int hextet = 0; hextet < option_length; hextet++) {
                    advertise_message->option_list[option_index].dns_recursive_name_server_t.dns_servers[hextet] = packet[index + 4 + hextet];
                }

                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:

                char *DSL_string = (char *)calloc(option_length, sizeof(char));
                valid_memory_allocation(DSL_string);
                for (int byte = 0; byte < option_length; byte++) {
                    DSL_string[byte] = packet[index + 4 + byte];
                }
                advertise_message->option_list[option_index].domain_search_list_t.search_list = DSL_string;

                break;

            case SOL_MAX_RT_OPTION_CODE: {
                uint32_t sol_max_rt = 0;
                for (int b = 0; b < 4; b++) {
                    sol_max_rt <<= ONE_BYTE_SHIFT;
                    sol_max_rt |= packet[index + 4 + b];
                }
                advertise_message->option_list[option_index].SOL_MAX_RT_t.SOL_MAX_RT_value = sol_max_rt;
                break;
            }

            case PREFERENCE_OPTION_CODE:
                advertise_message->option_list[option_index].preference_t.preference = (packet[index + 4] << 8) | packet[index + 5];
                break;

            default:
                break;
        }
        option_index++;
        index += (option_length + 4);
    }
    if (all_valid_options_included_counter != 11 &&
        all_valid_options_included_counter != 54 &&
        all_valid_options_included_counter != 62) {
        badAdvertisement = true;
    }
    if (badAdvertisement) {
        advertise_message->valid = false;
    } else {
        advertise_message->valid = true;
    }

    advertise_message->option_count = option_index;
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
    for (int i = 0; i < option_count; i++) {
        dhcpv6_option_t *opt = &advertisement->option_list[i];
        uint16_t option_code = opt->option_code;
        uint16_t option_length = opt->option_length;
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
                request->option_list[index].ia_na_t.t1 = 0;
                request->option_list[index].ia_na_t.t2 = 0;
                break;

            case IA_ADDR_OPTION_CODE:
                request->option_list[index].ia_address_t = advertisement->option_list[i].ia_address_t;
                request->option_list[index].ia_address_t.valid_lifetime = 0;
                request->option_list[index].ia_address_t.preferred_lifetime = 0;
                break;

            case IA_PD_OPTION_CODE:
                request->option_list[index].ia_pd_t = advertisement->option_list[i].ia_pd_t;
                request->option_list[index].ia_pd_t.t1 = 0;
                request->option_list[index].ia_pd_t.t2 = 0;
                break;

            case IAPREFIX_OPTION_CODE:
                request->option_list[index].ia_prefix_t = advertisement->option_list[i].ia_prefix_t;
                request->option_list[index].ia_prefix_t.valid_lifetime = 0;
                request->option_list[index].ia_prefix_t.preferred_lifetime = 0;
                break;

            case DNS_SERVERS_OPTION_CODE:
                request->option_list[index].dns_recursive_name_server_t = advertisement->option_list[i].dns_recursive_name_server_t;
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                request->option_list[index].domain_search_list_t.search_list = advertisement->option_list[i].domain_search_list_t.search_list;
                break;

            case SOL_MAX_RT_OPTION_CODE:
                request->option_list[index].SOL_MAX_RT_t.SOL_MAX_RT_value = advertisement->option_list[i].SOL_MAX_RT_t.SOL_MAX_RT_value;
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
        request->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
        request->option_list[index].option_request_t.option_request = (uint8_t *)calloc(request->option_list[index].option_length / OPTION_CODE_LENGTH_IN_ORO, sizeof(uint8_t));
        valid_memory_allocation(request->option_list[index].option_request_t.option_request);
        memcpy(request->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    request->option_count = index;

    return request;
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
    valid_socket(sent);

    return 0;
}

dhcpv6_message_t *parseReply(uint8_t *packet, dhcpv6_message_t *request, const char *iface, int size) {

    bool badReply = false;
    if (valid_transaction_id(packet[1], packet[2], packet[3]) != request->transaction_id) {
        badReply = true;
    }

    dhcpv6_message_t *reply = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(reply);

    // we need to declare iaoption_count here to prevent a syntax error
    uint8_t iaoption_count = 0;
    reply->option_count = get_option_count(packet, size, &iaoption_count);

    reply->option_list = (dhcpv6_option_t *)calloc(reply->option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(reply->option_list);

    IANA_t *iana = (IANA_t *)malloc(sizeof(IANA_t));
    IAPD_t *iapd = (IAPD_t *)malloc(sizeof(IAPD_t));

    bool ianaFound = false;
    bool iapdFound = false;

    int index = 4;
    int option_index = 0;
    int options_included_total = 0;
    for (int i = 0; i < reply->option_count; i++) {
        uint16_t option_code = reply->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];
        uint16_t option_length = reply->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];
        reply->option_list[option_index].option_code = option_code;
        reply->option_list[option_index].option_length = option_length;
        switch (option_code) {
            case STATUS_CODE_OPTION_CODE:
                uint8_t status_code = packet[index + 5];
                if (status_code) {
                    badReply = true;
                }

                break;

            case SERVER_ID_OPTION_CODE:
                options_included_total += SERVER_ID_OPTION_CODE;
                reply->option_list[option_index].server_id_t.duid.hw_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                reply->option_list[option_index].server_id_t.duid.hw_type = packet[index + 5] & ONE_BYTE_MASK;

                reply->option_list[option_index].server_id_t.duid.duid_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                reply->option_list[option_index].server_id_t.duid.duid_type = packet[index + 7] & ONE_BYTE_MASK;
                
                reply->option_list[option_index].server_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(reply->option_list[option_index].server_id_t.duid.mac);
                for (int x = 0; x < option_length; x++) {
                    reply->option_list[option_index].server_id_t.duid.mac[x] = packet[index + (x + 8)];
                }

                break;
            case CLIENT_ID_OPTION_CODE:
                options_included_total += CLIENT_ID_OPTION_CODE;
                reply->option_list[option_index].client_id_t.duid.duid_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                reply->option_list[option_index].client_id_t.duid.duid_type = packet[index + 5] & ONE_BYTE_MASK;

                if (reply->option_list[option_index].client_id_t.duid.duid_type != request->option_list[option_index].client_id_t.duid.duid_type) {
                    badReply = true;
                }

                reply->option_list[option_index].client_id_t.duid.hw_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;
                reply->option_list[option_index].client_id_t.duid.hw_type = packet[index + 7] & ONE_BYTE_MASK;

                if (reply->option_list[option_index].client_id_t.duid.hw_type != request->option_list[option_index].client_id_t.duid.hw_type) {
                    badReply = true;
                }

                reply->option_list[option_index].client_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(reply->option_list[option_index].client_id_t.duid.mac);
                for (int x = 0; x < MAC_ADDRESS_LENGTH; x++) {
                    reply->option_list[option_index].client_id_t.duid.mac[x] = packet[index + (x + 8)];
                    if (reply->option_list[option_index].client_id_t.duid.mac[x] != request->option_list[option_index].client_id_t.duid.mac[x]) {
                        badReply = true;
                    }
                }

                break;

            case IA_NA_OPTION_CODE:
                options_included_total += IA_NA_OPTION_CODE;
                ianaFound = true;
                for (int byte = 3; byte > -1; byte--) {
                    reply->option_list[option_index].ia_na_t.iaid |= (packet[index + (4 + byte)] << (8 * (3 - byte)));
                    reply->option_list[option_index].ia_na_t.t1 |= (packet[index + (8 + byte)] << (8 * (3 - byte)));
                    reply->option_list[option_index].ia_na_t.t2 |= (packet[index + (12 + byte)] << (8 * (3 - byte)));
                }
                
                iana->iaid = reply->option_list[option_index].ia_na_t.iaid;
                iana->t1 = reply->option_list[option_index].ia_na_t.t1;
                iana->t2 = reply->option_list[option_index].ia_na_t.t2;

                if (iana->t2 < iana->t1 && iana->t2 != 0 && iana->t1 != 0) { badReply = true; }

                option_index++;
                reply->option_list[option_index].option_code = packet[index + 17];
                if (reply->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {
                    int status_code = 0;
                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);
                    status_code |= packet[index + 21];

                    if (status_code) {
                        badReply = true;
                    }
                }

                options_included_total += IA_ADDR_OPTION_CODE;

                reply->option_list[option_index].option_length = 24;

                uint128_t address = 0;
                
                for (int byte = START_POINT_IN_READING_ADDRESS; byte > -1; byte--) {
                    address <<= ONE_BYTE_SHIFT;
                    address |= packet[index + 20 + (START_POINT_IN_READING_ADDRESS - byte)];
                }

                reply->option_list[option_index].ia_address_t.ipv6_address = address;

                for (int byte = 3; byte > -1; byte--) {
                    reply->option_list[option_index].ia_address_t.preferred_lifetime |= (packet[index + (36 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    reply->option_list[option_index].ia_address_t.valid_lifetime |= (packet[index + (40 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                iana->validlifetime = reply->option_list[option_index].ia_address_t.valid_lifetime;
                iana->preferredlifetime = reply->option_list[option_index].ia_address_t.preferred_lifetime;

                if (iana->preferredlifetime > iana->preferredlifetime) {badReply = true; }

                if (request->option_list[option_index].ia_address_t.ipv6_address !=
                    reply->option_list[option_index].ia_address_t.ipv6_address &&
                    request->message_type != REQUEST_MESSAGE_TYPE) {
                    badReply = true;
                }

                char cmd2[512];
                char address_string2[INET6_ADDRSTRLEN];
                uint128_to_ipv6_str(address, address_string2, sizeof(address_string2));
                sprintf(cmd2, "sudo ip -6 addr del %s/%d dev %s", address_string2, 128, iface);
                system(cmd2);

                char cmd[512];
                char address_string[INET6_ADDRSTRLEN];
                uint128_to_ipv6_str(address, address_string, sizeof(address_string));
                sprintf(cmd, "sudo ip -6 addr add %s/%d dev %s preferred_lft %lu valid_lft %lu", address_string, 128, iface, reply->option_list[option_index].ia_address_t.preferred_lifetime, reply->option_list[option_index].ia_address_t.valid_lifetime);
                system(cmd);
                
                char str[28];
                strcpy(str, address_string);
                iana->address = str;
                break;
            case IA_PD_OPTION_CODE:
               options_included_total += IA_PD_OPTION_CODE;
                iapdFound = true;
                for (int byte = 3; byte > -1; byte--) {
                    reply->option_list[option_index].ia_pd_t.iaid |= (packet[index + (4 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    reply->option_list[option_index].ia_pd_t.t1 |= (packet[index + (8 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                    reply->option_list[option_index].ia_pd_t.t2 |= (packet[index + (12 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                iapd->iaid = reply->option_list[option_index].ia_pd_t.iaid;
                iapd->t1 = reply->option_list[option_index].ia_pd_t.t1;
                iapd->t2 = reply->option_list[option_index].ia_pd_t.t2;
                if (iapd->t2 < iapd->t1 && iapd->t2 != 0 && iapd->t1 != 0) { badReply = true; }

                option_index++;
                options_included_total += IAPREFIX_OPTION_CODE;
                reply->option_list[option_index].option_code = packet[index + 17];
                if (reply->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {
                    int status_code = 0;
                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);
                    status_code |= packet[index + 21];

                    if (status_code) {
                        badReply = true;
                    }
                }

                reply->option_list[option_index].option_length = 25;

                uint128_t prefix = 0;
                
                for (int byte = START_POINT_IN_READING_ADDRESS; byte > -1; byte--) {
                    prefix <<= ONE_BYTE_SHIFT;
                    prefix |= packet[index + 29 + (START_POINT_IN_READING_ADDRESS - byte)];
                }
                iapd->validlifetime = reply->option_list[option_index].ia_prefix_t.valid_lifetime;
                iapd->preferredlifetime = reply->option_list[option_index].ia_prefix_t.preferred_lifetime;
                if (iapd->preferredlifetime > iapd->preferredlifetime) {badReply = true; }

                reply->option_list[option_index].ia_prefix_t.ipv6_prefix = prefix;

                for (int byte = 3; byte > -1; byte--) {
                    reply->option_list[option_index].ia_address_t.preferred_lifetime |= (packet[index + (20 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                for (int byte = 3; byte > -1; byte--) {
                    reply->option_list[option_index].ia_address_t.valid_lifetime |= (packet[index + (24 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));
                }

                reply->option_list[option_index].ia_prefix_t.prefix_length = packet[index + 28];

                if (request->option_list[option_index].ia_prefix_t.ipv6_prefix != 
                    reply->option_list[option_index].ia_prefix_t.ipv6_prefix
                    && request->message_type != REQUEST_MESSAGE_TYPE) {
                    badReply = true;
                }

                iapd->prefix = reply->option_list[option_index].ia_prefix_t.ipv6_prefix;
                iapd->prefix_length = reply->option_list[option_index].ia_prefix_t.prefix_length;

                break;

            case DNS_SERVERS_OPTION_CODE: {
                char cumulative_string2[400] = "";
                char address_string2[100];

                for (int address = 0; address < option_length / 16; address++) {
                    uint128_t DNSServerAddress = 0;

                    for (int byte = 15; byte > -1; byte--) {
                        DNSServerAddress <<= 8;
                        DNSServerAddress |= packet[index + 4 + (15 - byte) + (address * 16)];
                    }

                    uint128_to_ipv6_str(DNSServerAddress, address_string2, sizeof(address_string2));

                    char *updated = append_ipv6_address_if_unique(cumulative_string2, address_string2);
                    if (updated) {
                        strncpy(cumulative_string2, updated, sizeof(cumulative_string2) - 1);
                        cumulative_string2[sizeof(cumulative_string2) - 1] = '\0';
                        free(updated);
                    }

                }

                char cmd24[strlen(cumulative_string2) + strlen(iface) + 30];
                sprintf(cmd24, "sudo resolvectl dns %s %s\n", iface, cumulative_string2);
                system(cmd24);

                reply->option_list[option_index].dns_recursive_name_server_t.dns_servers = (uint8_t *)calloc(option_length, sizeof(uint8_t));
                valid_memory_allocation(reply->option_list[option_index].dns_recursive_name_server_t.dns_servers);
                for (int hextet = 0; hextet < option_length; hextet++) {
                    reply->option_list[option_index].dns_recursive_name_server_t.dns_servers[hextet] = packet[index + 4 + hextet];
                }

                break;
            }

            case DOMAIN_SEARCH_LIST_OPTION_CODE: {
                char domain_search_list[option_length + 1];
                strcpy(domain_search_list, "");

                for (int character = 1; character < option_length; character++) {
                    if (packet[index + character + 4] < 16 && !packet[index + (character - 1) + 4]) {
                        continue;
                    } else if (!packet[index + character + 4]) {
                        if (character + 1 == option_length) {
                            break;
                        }
                        strcat(domain_search_list, " ");
                    } else {
                        char fakeString[2];
                        if (packet[index + character + 4] > 15) {
                            fakeString[0] = packet[index + character + 4];
                        } else {
                            fakeString[0] = '.';
                        }
                        fakeString[1] = '\0';
                        strcat(domain_search_list, fakeString);
                    }
                }

                char cmd_23[strlen(domain_search_list) + strlen(iface) + 25];
                sprintf(cmd_23, "sudo resolvectl domain %s %s\n", iface, domain_search_list);
                system(cmd_23);
                
                char *DSL_string = (char *)calloc(option_length, sizeof(char));
                valid_memory_allocation(DSL_string);
                for (int byte = 0; byte < option_length; byte++) {
                    DSL_string[byte] = packet[index + 4 + byte];
                }
                reply->option_list[option_index].domain_search_list_t.search_list = DSL_string;
                
                break;
            }

            case SOL_MAX_RT_OPTION_CODE: {
                uint32_t sol_max_rt = 0;
                for (int b = 0; b < 4; b++) {
                    sol_max_rt <<= ONE_BYTE_SHIFT;
                    sol_max_rt |= packet[index + 4 + b];
                }
                reply->option_list[option_index].SOL_MAX_RT_t.SOL_MAX_RT_value = sol_max_rt;
                break;
            }

            case PREFERENCE_OPTION_CODE:
                // Preference is a 2-byte value
                reply->option_list[option_index].preference_t.preference = (packet[index + 4] << 8) | packet[index + 5];
                break;

            default:
                break;
        }
        option_index++;
        index += (option_length + 4);
    }
    if (options_included_total != 11 &&
        options_included_total != 54 &&
        options_included_total != 62) {
        badReply= true;
    }
    reply->valid = !badReply;
    if (ianaFound && !iapdFound) {
        writeLease(iana, NULL, iface);
    } else if (!ianaFound && iapdFound) {
        writeLease(NULL, iapd, iface);
    } else if (ianaFound && iapdFound) {
        writeLease(iana, iapd, iface);
    } else {
        writeLease(NULL, NULL, iface);
    }
    return reply;
}

dhcpv6_message_t * buildRenew(dhcpv6_message_t *reply, config_t *config) {
    uint8_t option_count = reply->option_count;

   dhcpv6_message_t *renew = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
   valid_memory_allocation(renew);

    renew->message_type = RENEW_MESSAGE_TYPE;
    renew->transaction_id = rand() & THREE_BYTE_MASK;

    renew->option_list = calloc(option_count + 2, sizeof(dhcpv6_option_t));
    valid_memory_allocation(renew->option_list);

    size_t index = 0;
    for (int i = 0; i < option_count; i++) {
        dhcpv6_option_t *opt = &reply->option_list[i];
        uint16_t option_code = opt->option_code;
        uint16_t option_length = opt->option_length;
        renew->option_list[index].option_code = option_code;
        renew->option_list[index].option_length = option_length;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                renew->option_list[index].client_id_t = reply->option_list[i].client_id_t;
                break;

            case SERVER_ID_OPTION_CODE:
                renew->option_list[index].server_id_t = reply->option_list[i].server_id_t;
                break;

            case IA_NA_OPTION_CODE:
                renew->option_list[index].ia_na_t = reply->option_list[i].ia_na_t;
                renew->option_list[index].ia_na_t.t1 = 0;
                renew->option_list[index].ia_na_t.t2 = 0;
                break;

            case IA_ADDR_OPTION_CODE:
                renew->option_list[index].ia_address_t = reply->option_list[i].ia_address_t;
                renew->option_list[index].ia_address_t.valid_lifetime = 0;
                renew->option_list[index].ia_address_t.preferred_lifetime = 0;
                break;

            case IA_PD_OPTION_CODE:
                renew->option_list[index].ia_pd_t = reply->option_list[i].ia_pd_t;
                renew->option_list[index].ia_pd_t.t1 = 0;
                renew->option_list[index].ia_pd_t.t2 = 0;
                break;

            case IAPREFIX_OPTION_CODE:
                renew->option_list[index].ia_prefix_t = reply->option_list[i].ia_prefix_t;
                renew->option_list[index].ia_prefix_t.valid_lifetime = 0;
                renew->option_list[index].ia_prefix_t.preferred_lifetime = 0;
                break;

            case DNS_SERVERS_OPTION_CODE:
                renew->option_list[index].dns_recursive_name_server_t = reply->option_list[i].dns_recursive_name_server_t;
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                renew->option_list[index].domain_search_list_t.search_list = reply->option_list[i].domain_search_list_t.search_list;
                break;

            default:
                break;
        }

        index++;
    }

    renew->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    renew->option_list[index].option_length = 2;
    renew->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    if (config->oro_list_length > 0) {
        renew->option_list[index].option_code = ORO_OPTION_CODE;
        renew->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
        renew->option_list[index].option_request_t.option_request = (uint8_t *)calloc(renew->option_list[index].option_length / OPTION_CODE_LENGTH_IN_ORO, sizeof(uint8_t));
        valid_memory_allocation(renew->option_list[index].option_request_t.option_request);
        memcpy(renew->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    renew->option_count = index;

    return renew;
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
    valid_socket(sent);

    return 0;
}

dhcpv6_message_t * buildRebind(dhcpv6_message_t *reply, config_t *config) {
    uint8_t option_count = reply->option_count;

    dhcpv6_message_t *rebind = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(rebind);

    rebind->message_type = REBIND_MESSAGE_TYPE;
    rebind->transaction_id = rand() & THREE_BYTE_MASK;

    rebind->option_list = calloc(option_count + 1, sizeof(dhcpv6_option_t));
    valid_memory_allocation(rebind->option_list);

    size_t index = 0;
    for (int i = 0; i < option_count; i++) {
        dhcpv6_option_t *opt = &reply->option_list[i];
        uint16_t option_code = opt->option_code;
        uint16_t option_length = opt->option_length;
        rebind->option_list[index].option_code = option_code;
        rebind->option_list[index].option_length = option_length;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                rebind->option_list[index].client_id_t = reply->option_list[i].client_id_t;
                break;

            case IA_NA_OPTION_CODE:
                rebind->option_list[index].ia_na_t = reply->option_list[i].ia_na_t;
                break;

            case IA_ADDR_OPTION_CODE:
                rebind->option_list[index].ia_address_t = reply->option_list[i].ia_address_t;
                break;

            case IA_PD_OPTION_CODE:
                rebind->option_list[index].ia_pd_t = reply->option_list[i].ia_pd_t;
                break;

            case IAPREFIX_OPTION_CODE:
                rebind->option_list[index].ia_prefix_t = reply->option_list[i].ia_prefix_t;
                break;

            case DNS_SERVERS_OPTION_CODE:
                rebind->option_list[index].dns_recursive_name_server_t = reply->option_list[i].dns_recursive_name_server_t;
                break;

            case DOMAIN_SEARCH_LIST_OPTION_CODE:
                rebind->option_list[index].domain_search_list_t.search_list = reply->option_list[i].domain_search_list_t.search_list;
                break;

            default:
                break;
        }

        index++;
    }

    rebind->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    rebind->option_list[index].option_length = 2;
    rebind->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    if (config->oro_list_length > 0) {
        rebind->option_list[index].option_code = ORO_OPTION_CODE;
        rebind->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
        rebind->option_list[index].option_request_t.option_request = (uint8_t *)calloc(rebind->option_list[index].option_length / OPTION_CODE_LENGTH_IN_ORO, sizeof(uint8_t));
        valid_memory_allocation(rebind->option_list[index].option_request_t.option_request);
        memcpy(rebind->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    rebind->option_count = index;

    return rebind;
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
    valid_socket(sent);

    return 0;
}

dhcpv6_message_t * buildDecline(dhcpv6_message_t *reply, config_t *config) {
    uint8_t option_count = 6;

   dhcpv6_message_t *decline = (dhcpv6_message_t *)malloc(sizeof(dhcpv6_message_t));
   valid_memory_allocation(decline);

    decline->message_type = DECLINE_MESSAGE_TYPE;
    decline->transaction_id = rand() & THREE_BYTE_MASK;

    decline->option_list = calloc(option_count, sizeof(dhcpv6_option_t));
    valid_memory_allocation(decline->option_list);

    size_t index = 0;
    for (int i = 0; i < reply->option_count; i++) {
        dhcpv6_option_t *opt = &reply->option_list[i];
        uint16_t option_code = opt->option_code;
        uint16_t option_length = opt->option_length;
        switch (opt->option_code) {
            case CLIENT_ID_OPTION_CODE:
                decline->option_list[index].option_code = option_code;
                decline->option_list[index].option_length = option_length;
                decline->option_list[index].client_id_t = reply->option_list[i].client_id_t;
                index++;
                break;

            case SERVER_ID_OPTION_CODE:
                decline->option_list[index].option_code = option_code;
                decline->option_list[index].option_length = option_length;    
                decline->option_list[index].server_id_t = reply->option_list[i].server_id_t;
                index++;
                break;

            case IA_NA_OPTION_CODE:
                decline->option_list[index].option_code = option_code;
                decline->option_list[index].option_length = option_length;                  
                decline->option_list[index].ia_na_t = reply->option_list[i].ia_na_t;
                decline->option_list[index].ia_na_t.t1 = 0;
                decline->option_list[index].ia_na_t.t2 = 0;
                index++;
                break;

            case IA_ADDR_OPTION_CODE:
                decline->option_list[index].option_code = option_code;
                decline->option_list[index].option_length = option_length;      
                decline->option_list[index].ia_address_t = reply->option_list[i].ia_address_t;
                decline->option_list[index].ia_address_t.valid_lifetime = 0;
                decline->option_list[index].ia_address_t.preferred_lifetime = 0;
                index++;
                break;

            default:
                break;
        }

        index++;
    }

    decline->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    decline->option_list[index].option_length = 2;
    decline->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    if (config->oro_list_length > 0) {
        decline->option_list[index].option_code = ORO_OPTION_CODE;
        decline->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
        decline->option_list[index].option_request_t.option_request = (uint8_t *)calloc(decline->option_list[index].option_length / OPTION_CODE_LENGTH_IN_ORO, sizeof(uint8_t));
        valid_memory_allocation(decline->option_list[index].option_request_t.option_request);
        memcpy(decline->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    decline->option_count = index;

    return decline;
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
    valid_socket(sent);

    return 0;
}

