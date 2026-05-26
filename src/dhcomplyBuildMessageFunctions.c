#include "dhcomplyBuildMessageFunctions.h"

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

        msg->option_list[index].ia_na_t.iaid = getIAID(config->ianaIaid);

        msg->option_list[index].ia_na_t.t1 = 0;

        msg->option_list[index].ia_na_t.t2 = 0;

        index++;

    }

    // IA_PD

    if (config->pd) {

        msg->option_list[index].option_code = IA_PD_OPTION_CODE;

        msg->option_list[index].option_length = 12;

        msg->option_list[index].ia_pd_t.iaid = getIAID(config->iapdIaid);

        msg->option_list[index].ia_pd_t.t1 = 0;

        msg->option_list[index].ia_pd_t.t2 = 0;

        index++;

    }

    msg->option_count = option_count;

    return msg;

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

dhcpv6_message_t * buildDecline(dhcpv6_message_t *reply, config_t *config) {

    (void)config;

    uint8_t option_count = 1;

    for (int i = 0; i < reply->option_count; i++) {

        switch (reply->option_list[i].option_code) {

            case CLIENT_ID_OPTION_CODE:

            case SERVER_ID_OPTION_CODE:

            case IA_NA_OPTION_CODE:

            case IA_ADDR_OPTION_CODE:

                option_count++;

                break;

            default:

                continue;

        }

    }

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

                break;

            case SERVER_ID_OPTION_CODE:

                decline->option_list[index].option_code = option_code;

                decline->option_list[index].option_length = option_length;

                decline->option_list[index].server_id_t = reply->option_list[i].server_id_t;

                break;

            case IA_NA_OPTION_CODE:

                decline->option_list[index].option_code = option_code;

                decline->option_list[index].option_length = option_length;

                decline->option_list[index].ia_na_t = reply->option_list[i].ia_na_t;

                decline->option_list[index].ia_na_t.t1 = 0;

                decline->option_list[index].ia_na_t.t2 = 0;

                break;

            case IA_ADDR_OPTION_CODE:

                decline->option_list[index].option_code = option_code;

                decline->option_list[index].option_length = option_length;

                decline->option_list[index].ia_address_t = reply->option_list[i].ia_address_t;

                decline->option_list[index].ia_address_t.valid_lifetime = 0;

                decline->option_list[index].ia_address_t.preferred_lifetime = 0;

                break;

            default:

                continue;

        }

        index++;

    }

    decline->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;

    decline->option_list[index].option_length = 2;

    decline->option_list[index].elapsed_time_t.elapsed_time_value = 0;

    index++;

    decline->option_count = index;

    return decline;

}

dhcpv6_message_t *buildInformationRequest(config_t *config, const char *ifname) {

    size_t option_count = 2;

    if (config->oro_list_length > 0) option_count++;

    dhcpv6_message_t *msg = malloc(sizeof(dhcpv6_message_t));

    valid_memory_allocation(msg);

    msg->message_type = INFORMATION_REQUEST_MESSAGE_TYPE;

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

    msg->option_count = option_count;

    return msg;

}

dhcpv6_message_t *buildConfirm(config_t *config, const char *ifname) {

    cJSON *lease_json = readLease(ifname);
    if (!lease_json) {
        return NULL;
    }

    size_t option_count = 2;

    cJSON *server_duid = cJSON_GetObjectItemCaseSensitive(lease_json, "server_duid");
    if (cJSON_IsObject(server_duid)) option_count++;

    cJSON *leases = cJSON_GetObjectItemCaseSensitive(lease_json, "leases");
    if (!cJSON_IsArray(leases)) {
        cJSON_Delete(lease_json);
        return NULL;
    }

    cJSON *lease = NULL;
    cJSON_ArrayForEach(lease, leases) {
        cJSON *type = cJSON_GetObjectItemCaseSensitive(lease, "type");
        if (cJSON_IsString(type) &&
            (!strcmp(type->valuestring, "IANA") || !strcmp(type->valuestring, "IAPD"))) {
            option_count += 2;
        }
    }

    if (config->oro_list_length > 0) option_count++;
    if (config->reconfigure) option_count++;

    dhcpv6_message_t *msg = malloc(sizeof(dhcpv6_message_t));
    valid_memory_allocation(msg);
    msg->message_type = CONFIRM_MESSAGE_TYPE;
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
    free(mac);
    index++;

    if (cJSON_IsObject(server_duid)) {
        cJSON *duid_type = cJSON_GetObjectItemCaseSensitive(server_duid, "duid_type");
        cJSON *duid = cJSON_GetObjectItemCaseSensitive(server_duid, "duid");

        if (!cJSON_IsNumber(duid_type) || !cJSON_IsString(duid)) {
            cJSON_Delete(lease_json);
            return NULL;
        }

        uint8_t duid_bytes[128];
        size_t duid_len = 0;
        const char *hex = duid->valuestring;

        while (*hex && duid_len < sizeof(duid_bytes)) {
            while (*hex == ':') hex++;

            if (!isxdigit((unsigned char)hex[0]) ||
                !isxdigit((unsigned char)hex[1])) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            uint8_t high = 0;
            uint8_t low = 0;

            if (hex[0] >= '0' && hex[0] <= '9') high = hex[0] - '0';
            else if (hex[0] >= 'a' && hex[0] <= 'f') high = hex[0] - 'a' + 10;
            else if (hex[0] >= 'A' && hex[0] <= 'F') high = hex[0] - 'A' + 10;

            if (hex[1] >= '0' && hex[1] <= '9') low = hex[1] - '0';
            else if (hex[1] >= 'a' && hex[1] <= 'f') low = hex[1] - 'a' + 10;
            else if (hex[1] >= 'A' && hex[1] <= 'F') low = hex[1] - 'A' + 10;

            duid_bytes[duid_len++] = (high << 4) | low;
            hex += 2;

            if (*hex && *hex != ':') {
                cJSON_Delete(lease_json);
                return NULL;
            }
        }

        if (*hex || duid_len < 4) {
            cJSON_Delete(lease_json);
            return NULL;
        }

        msg->option_list[index].option_code = SERVER_ID_OPTION_CODE;
        msg->option_list[index].option_length = duid_len;
        msg->option_list[index].server_id_t.duid.duid_type =
            (duid_bytes[0] << ONE_BYTE_SHIFT) | duid_bytes[1];
        msg->option_list[index].server_id_t.duid.hw_type =
            (duid_bytes[2] << ONE_BYTE_SHIFT) | duid_bytes[3];

        if (msg->option_list[index].server_id_t.duid.duid_type != duid_type->valueint) {
            cJSON_Delete(lease_json);
            return NULL;
        }

        size_t server_duid_data_len = duid_len - 4;
        msg->option_list[index].server_id_t.duid.mac =
            (uint8_t *)calloc(server_duid_data_len, sizeof(uint8_t));
        valid_memory_allocation(msg->option_list[index].server_id_t.duid.mac);

        for (size_t i = 0; i < server_duid_data_len; i++) {
            msg->option_list[index].server_id_t.duid.mac[i] = duid_bytes[i + 4];
        }

        index++;
    }

    msg->option_list[index].option_code = ELAPSED_TIME_OPTION_CODE;
    msg->option_list[index].option_length = 2;
    msg->option_list[index].elapsed_time_t.elapsed_time_value = 0;
    index++;

    if (config->oro_list_length > 0) {
        msg->option_list[index].option_code = ORO_OPTION_CODE;
        msg->option_list[index].option_length = config->oro_list_length * OPTION_CODE_LENGTH_IN_ORO;
        msg->option_list[index].option_request_t.option_request = (uint8_t *)malloc(msg->option_list[index].option_length);
        valid_memory_allocation(msg->option_list[index].option_request_t.option_request);
        memcpy(msg->option_list[index].option_request_t.option_request, config->oro_list, config->oro_list_length);
        index++;
    }

    if (config->reconfigure) {
        msg->option_list[index].option_code = RECONF_ACCEPT_OPTION_CODE;
        msg->option_list[index].option_length = 0;
        index++;
    }

    cJSON_ArrayForEach(lease, leases) {
        cJSON *type = cJSON_GetObjectItemCaseSensitive(lease, "type");
        cJSON *iaid = cJSON_GetObjectItemCaseSensitive(lease, "iaid");
        cJSON *t1 = cJSON_GetObjectItemCaseSensitive(lease, "t1");
        cJSON *t2 = cJSON_GetObjectItemCaseSensitive(lease, "t2");
        cJSON *preferred_lifetime = cJSON_GetObjectItemCaseSensitive(lease, "preferred_lifetime");
        cJSON *valid_lifetime = cJSON_GetObjectItemCaseSensitive(lease, "valid_lifetime");

        if (!cJSON_IsString(type) ||
            !cJSON_IsString(iaid) ||
            !cJSON_IsNumber(t1) ||
            !cJSON_IsNumber(t2) ||
            !cJSON_IsNumber(preferred_lifetime) ||
            !cJSON_IsNumber(valid_lifetime)) {
            cJSON_Delete(lease_json);
            return NULL;
        }

        if (!strcmp(type->valuestring, "IANA")) {
            cJSON *address = cJSON_GetObjectItemCaseSensitive(lease, "address");
            if (!cJSON_IsString(address)) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            msg->option_list[index].option_code = IA_NA_OPTION_CODE;
            msg->option_list[index].option_length = 12 + 4 + 24;
            msg->option_list[index].ia_na_t.iaid = strtoul(iaid->valuestring, NULL, 16);
            msg->option_list[index].ia_na_t.t1 = t1->valueint;
            msg->option_list[index].ia_na_t.t2 = t2->valueint;
            index++;

            msg->option_list[index].option_code = IA_ADDR_OPTION_CODE;
            msg->option_list[index].option_length = 24;
            msg->option_list[index].ia_address_t.preferred_lifetime = preferred_lifetime->valueint;
            msg->option_list[index].ia_address_t.valid_lifetime = valid_lifetime->valueint;

            struct in6_addr addr;
            if (inet_pton(AF_INET6, address->valuestring, &addr) != 1) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            uint128_t parsed_address = 0;
            for (int i = 0; i < 16; i++) {
                parsed_address <<= ONE_BYTE_SHIFT;
                parsed_address |= addr.s6_addr[i];
            }

            msg->option_list[index].ia_address_t.ipv6_address = parsed_address;
            index++;
        }
        else if (!strcmp(type->valuestring, "IAPD")) {
            cJSON *prefix = cJSON_GetObjectItemCaseSensitive(lease, "prefix");
            cJSON *prefix_length = cJSON_GetObjectItemCaseSensitive(lease, "prefix_length");

            if (!cJSON_IsString(prefix) || !cJSON_IsNumber(prefix_length)) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            msg->option_list[index].option_code = IA_PD_OPTION_CODE;
            msg->option_list[index].option_length = 12 + 4 + 25;
            msg->option_list[index].ia_pd_t.iaid = strtoul(iaid->valuestring, NULL, 16);
            msg->option_list[index].ia_pd_t.t1 = t1->valueint;
            msg->option_list[index].ia_pd_t.t2 = t2->valueint;
            index++;

            msg->option_list[index].option_code = IAPREFIX_OPTION_CODE;
            msg->option_list[index].option_length = 25;
            msg->option_list[index].ia_prefix_t.prefix_length = prefix_length->valueint;
            msg->option_list[index].ia_prefix_t.preferred_lifetime = preferred_lifetime->valueint;
            msg->option_list[index].ia_prefix_t.valid_lifetime = valid_lifetime->valueint;

            char prefix_address[INET6_ADDRSTRLEN];
            if (sscanf(prefix->valuestring, "%45[^/]", prefix_address) != 1) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            struct in6_addr addr;
            if (inet_pton(AF_INET6, prefix_address, &addr) != 1) {
                cJSON_Delete(lease_json);
                return NULL;
            }

            uint128_t parsed_prefix = 0;
            for (int i = 0; i < 16; i++) {
                parsed_prefix <<= ONE_BYTE_SHIFT;
                parsed_prefix |= addr.s6_addr[i];
            }

            msg->option_list[index].ia_prefix_t.ipv6_prefix = parsed_prefix;
            index++;
        }
    }

    msg->option_count = index;
    cJSON_Delete(lease_json);
    return msg;
}
