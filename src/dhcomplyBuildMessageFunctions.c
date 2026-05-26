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
