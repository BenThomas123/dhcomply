#include "dhcomplyParseMessageFunctions.h"

static int get_message_option_index(dhcpv6_message_t *message, uint16_t option_code) {
    for (int index = 0; index < message->option_count; index++) {
        if (message->option_list[index].option_code == option_code) {
            return index;
        }
    }

    return -1;
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

            case STATUS_CODE_OPTION_CODE: {

                uint8_t status_code = packet[index + 5];

                if (status_code) {

                    badAdvertisement = true;

                }

                break;
            }

            case SERVER_ID_OPTION_CODE:

                all_valid_options_included_counter += SERVER_ID_OPTION_CODE;

                advertise_message->option_list[option_index].server_id_t.duid.duid_type =
                    packet[index + 4] << ONE_BYTE_SHIFT | packet[index + 5];

                advertise_message->option_list[option_index].server_id_t.duid.hw_type =
                    packet[index + 6] << ONE_BYTE_SHIFT | packet[index + 7];

                advertise_message->option_list[option_index].server_id_t.duid.mac =
                    (uint8_t *)calloc(option_length - 4, sizeof(uint8_t));

                valid_memory_allocation(advertise_message->option_list[option_index].server_id_t.duid.mac);

                for (int x = 0; x < option_length - 4; x++) {

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

                for (int byte = 15; byte > -1; byte--) {

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

            case DOMAIN_SEARCH_LIST_OPTION_CODE: {

                char *DSL_string = (char *)calloc(option_length, sizeof(char));

                valid_memory_allocation(DSL_string);

                for (int byte = 0; byte < option_length; byte++) {

                    DSL_string[byte] = packet[index + 4 + byte];

                }

                advertise_message->option_list[option_index].domain_search_list_t.search_list = DSL_string;

                break;
            }

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

                advertise_message->option_list[option_index].preference_t.preference_value = packet[index + 4];

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

dhcpv6_message_t *parseReply(uint8_t *packet, dhcpv6_message_t *request, const char *iface, int size) {

    bool badReply = false;
    int request_client_id_index =
        get_message_option_index(request, CLIENT_ID_OPTION_CODE);

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

    duid_ll_t *server_duid = NULL;

    size_t server_duid_mac_length = 0;

    int index = 4;

    int option_index = 0;

    int options_included_total = 0;

    bool validRapid =
        get_message_option_index(request, RAPID_COMMIT_OPTION_CODE) == -1;

    for (int i = 0; i < reply->option_count - iaoption_count; i++) {

        uint16_t option_code = reply->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];

        uint16_t option_length = reply->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];

        reply->option_list[option_index].option_code = option_code;

        reply->option_list[option_index].option_length = option_length;

        fprintf(stderr, "option code: %d bad reply: %d\n", option_code, badReply);

        switch (option_code) {

            case RAPID_COMMIT_OPTION_CODE:
                validRapid = true;
                break;

            case STATUS_CODE_OPTION_CODE: {

                uint8_t status_code = packet[index + 5];

                if (status_code) {
                    badReply = true;
                    fprintf(stderr, "reply failed: status code\n");
                    if (status_code == NOTONLINK_STATUS_CODE) {
                        return NULL;
                    }
                }

                break;
            }

            case SERVER_ID_OPTION_CODE:

                options_included_total += SERVER_ID_OPTION_CODE;

                reply->option_list[option_index].server_id_t.duid.duid_type =
                    packet[index + 4] << ONE_BYTE_SHIFT | packet[index + 5];

                reply->option_list[option_index].server_id_t.duid.hw_type =
                    packet[index + 6] << ONE_BYTE_SHIFT | packet[index + 7];

                reply->option_list[option_index].server_id_t.duid.mac =
                    (uint8_t *)calloc(option_length - 4, sizeof(uint8_t));

                valid_memory_allocation(reply->option_list[option_index].server_id_t.duid.mac);

                for (int x = 0; x < option_length - 4; x++) {

                    reply->option_list[option_index].server_id_t.duid.mac[x] = packet[index + (x + 8)];

                }

                server_duid = &reply->option_list[option_index].server_id_t.duid;

                server_duid_mac_length = option_length - 4;

                break;

            case CLIENT_ID_OPTION_CODE:

                options_included_total += CLIENT_ID_OPTION_CODE;

                if (request_client_id_index == -1) {
                    badReply = true;
                    break;
                }

                reply->option_list[option_index].client_id_t.duid.duid_type = (packet[index + 4] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;

                reply->option_list[option_index].client_id_t.duid.duid_type = packet[index + 5] & ONE_BYTE_MASK;

                if (reply->option_list[option_index].client_id_t.duid.duid_type !=
                    request->option_list[request_client_id_index].client_id_t.duid.duid_type) {
                    fprintf(stderr, "duid type did not match\n");

                    badReply = true;

                }

                reply->option_list[option_index].client_id_t.duid.hw_type = (packet[index + 6] >> ONE_BYTE_SHIFT) & ONE_BYTE_MASK;

                reply->option_list[option_index].client_id_t.duid.hw_type = packet[index + 7] & ONE_BYTE_MASK;

                if (reply->option_list[option_index].client_id_t.duid.hw_type !=
                    request->option_list[request_client_id_index].client_id_t.duid.hw_type) {

                    badReply = true;

                }

                reply->option_list[option_index].client_id_t.duid.mac = (uint8_t *)calloc(option_length, sizeof(uint8_t));

                valid_memory_allocation(reply->option_list[option_index].client_id_t.duid.mac);

                for (int x = 0; x < MAC_ADDRESS_LENGTH; x++) {

                    reply->option_list[option_index].client_id_t.duid.mac[x] = packet[index + (x + 8)];

                    if (reply->option_list[option_index].client_id_t.duid.mac[x] !=
                        request->option_list[request_client_id_index].client_id_t.duid.mac[x]) {

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

                reply->option_list[option_index].option_code = packet[index + 16] << ONE_BYTE_SHIFT;

                reply->option_list[option_index].option_code |= packet[index + 17];

                if (reply->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {

                    int status_code = 0;

                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);

                    status_code |= packet[index + 21];

                    if (status_code) {

                        badReply = true;

                    }

                }

                options_included_total += IA_ADDR_OPTION_CODE;

                reply->option_list[option_index].option_length = packet[index + 18] << ONE_BYTE_SHIFT;

                reply->option_list[option_index].option_length |= packet[index + 19];

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

                if (iana->preferredlifetime > iana->validlifetime) {
                    fprintf(stderr, "reply failed: valid lifetime not greater than prefered\n");
                    badReply = true;
				}

                if (request->message_type != SOLICIT_MESSAGE_TYPE &&
                    request->message_type != REQUEST_MESSAGE_TYPE &&
                    request->message_type != REBIND_MESSAGE_TYPE &&
                    request->message_type != RELEASE_MESSAGE_TYPE &&
                    request->option_list[option_index].ia_address_t.ipv6_address !=
                        reply->option_list[option_index].ia_address_t.ipv6_address) {

                    fprintf(stderr, "reply failed: because expected request \n");
                    badReply = true;
                }

                char cmd2[512];

                char address_string2[INET6_ADDRSTRLEN];

                uint128_to_ipv6_str(address, address_string2, sizeof(address_string2));

				sprintf(cmd2, "sudo ip -6 addr del %s/%d dev %s > /dev/null 2>&1", address_string2, 128, iface);
				system(cmd2);

                char cmd[512];

                char address_string[INET6_ADDRSTRLEN];

                uint128_to_ipv6_str(address, address_string, sizeof(address_string));
                if (request->message_type != RELEASE_MESSAGE_TYPE) {
                    sprintf(cmd, "sudo ip -6 addr add %s/%d dev %s preferred_lft %lu valid_lft %lu", address_string, 128, iface, reply->option_list[option_index].ia_address_t.preferred_lifetime, reply->option_list[option_index].ia_address_t.valid_lifetime);
                    system(cmd);
                }

                iana->address = strdup(address_string);

                valid_memory_allocation(iana->address);

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

                if (iapd->t2 < iapd->t1 && iapd->t2 != 0 && iapd->t1 != 0) {
                    badReply = true;
                    fprintf(stderr, "reply failed for some reason: status code");
                }

                option_index++;

                options_included_total += IAPREFIX_OPTION_CODE;

                reply->option_list[option_index].option_code = packet[index + 16] << ONE_BYTE_SHIFT;

                reply->option_list[option_index].option_code |= packet[index + 17];

                if (reply->option_list[option_index].option_code == STATUS_CODE_OPTION_CODE) {

                    int status_code = 0;

                    status_code |= (packet[index + 20] << ONE_BYTE_SHIFT);

                    status_code |= packet[index + 21];

                    if (status_code) {
                        fprintf(stderr, "reply failed for some reason: status code");

                        badReply = true;

                    }

                }

                reply->option_list[option_index].option_length = packet[index + 18] << ONE_BYTE_SHIFT;

                reply->option_list[option_index].option_length |= packet[index + 19];

                uint128_t prefix = 0;

                for (int byte = START_POINT_IN_READING_ADDRESS; byte > -1; byte--) {

                    prefix <<= ONE_BYTE_SHIFT;

                    prefix |= packet[index + 29 + (START_POINT_IN_READING_ADDRESS - byte)];

                }

                reply->option_list[option_index].ia_prefix_t.ipv6_prefix = prefix;

                for (int byte = 3; byte > -1; byte--) {

                    reply->option_list[option_index].ia_prefix_t.preferred_lifetime |= (packet[index + (20 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));

                }

                for (int byte = 3; byte > -1; byte--) {

                    reply->option_list[option_index].ia_prefix_t.valid_lifetime |= (packet[index + (24 + byte)] << (ONE_BYTE_SHIFT * (3 - byte)));

                }

                reply->option_list[option_index].ia_prefix_t.prefix_length = packet[index + 28];

                iapd->validlifetime = reply->option_list[option_index].ia_prefix_t.valid_lifetime;

                iapd->preferredlifetime = reply->option_list[option_index].ia_prefix_t.preferred_lifetime;

                if (iapd->preferredlifetime > iapd->validlifetime) {badReply = true; }

                if (request->message_type != SOLICIT_MESSAGE_TYPE &&
                    request->message_type != REQUEST_MESSAGE_TYPE &&
                    request->message_type != REBIND_MESSAGE_TYPE &&
                    request->message_type != RELEASE_MESSAGE_TYPE &&
                    request->option_list[option_index].ia_prefix_t.ipv6_prefix !=
                        reply->option_list[option_index].ia_prefix_t.ipv6_prefix) {

                    badReply = true;
                    fprintf(stderr, "reply failed for some reason");
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

                reply->option_list[option_index].preference_t.preference_value = packet[index + 4];

                break;

            default:

                break;

        }

        option_index++;

        index += (option_length + 4);

    }

    fprintf(stdout, "\nafter loop badreply: %d\n", badReply);
    if (
        (options_included_total != 3 && request->message_type == CONFIRM_MESSAGE_TYPE) &&

        options_included_total != 62 &&

        options_included_total != 11 &&

        options_included_total != 54) {

        fprintf(stderr, "reply failed: missing required options\n");
        badReply = true;

    }

    if (!validRapid) {
        badReply = true;
    }

    reply->valid = !badReply;

    if (reply->valid) {
        if (ianaFound && !iapdFound) {
            writeLease(iana, NULL, iface, server_duid, server_duid_mac_length);
        } else if (!ianaFound && iapdFound) {
            writeLease(NULL, iapd, iface, server_duid, server_duid_mac_length);
        } else if (ianaFound && iapdFound) {
            writeLease(iana, iapd, iface, server_duid, server_duid_mac_length);
        } else {
            if (!(options_included_total == 3 && request->message_type == CONFIRM_MESSAGE_TYPE)) {
                fprintf(stderr, "reply failed\n");
                reply->valid = false;
            }
		}
    }
    fprintf(stdout, "\nafter loop badreply: %d\n", badReply);
    fprintf(stdout, "\nafter loop badreply: %d\n", reply->valid);

    return reply;

}

dhcpv6_message_t *parseStatelessReply(uint8_t *packet, dhcpv6_message_t *request, const char *iface, int size) {

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

    int index = 4;

    int option_index = 0;

    int options_included_total = 0;

    for (int i = 0; i < reply->option_count; i++) {

        uint16_t option_code = reply->option_list[option_index].option_code = packet[index] << 8 | packet[index + 1];

        uint16_t option_length = reply->option_list[option_index].option_length = packet[index + 2] << 8 | packet[index + 3];

        reply->option_list[option_index].option_code = option_code;

        reply->option_list[option_index].option_length = option_length;

        switch (option_code) {

            case STATUS_CODE_OPTION_CODE: {

                uint8_t status_code = packet[index + 5];

                if (status_code) {

                    badReply = true;

                }

                break;
            }

            case SERVER_ID_OPTION_CODE:

                options_included_total += SERVER_ID_OPTION_CODE;

                reply->option_list[option_index].server_id_t.duid.duid_type =
                    packet[index + 4] << ONE_BYTE_SHIFT | packet[index + 5];

                reply->option_list[option_index].server_id_t.duid.hw_type =
                    packet[index + 6] << ONE_BYTE_SHIFT | packet[index + 7];

                reply->option_list[option_index].server_id_t.duid.mac =
                    (uint8_t *)calloc(option_length - 4, sizeof(uint8_t));

                valid_memory_allocation(reply->option_list[option_index].server_id_t.duid.mac);

                for (int x = 0; x < option_length - 4; x++) {

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

            case INF_MAX_RT_OPTION_CODE: {

                uint32_t inf_max_rt = 0;

                for (int b = 0; b < 4; b++) {

                    inf_max_rt <<= ONE_BYTE_SHIFT;

                    inf_max_rt |= packet[index + 4 + b];

                }

                reply->option_list[option_index].INF_MAX_RT_t.INF_MAX_RT_value = inf_max_rt;

                break;

            }

            case PREFERENCE_OPTION_CODE:

                reply->option_list[option_index].preference_t.preference_value = packet[index + 4];

                break;

            case INFORMATION_REFRESH_OPTION_CODE: {

                uint32_t refresh_time = 0;

                for (int b = 0; b < 4; b++) {

                    refresh_time <<= ONE_BYTE_SHIFT;

                    refresh_time |= packet[index + 4 + b];

                }

                reply->option_list[option_index].information_refresh_time_t.information_refresh_time = refresh_time;

                break;
            }

            default:

                break;

        }

        option_index++;

        index += (option_length + 4);

    }

    if (options_included_total != CLIENT_ID_OPTION_CODE + SERVER_ID_OPTION_CODE) {

        badReply = true;

    }

    reply->valid = !badReply;

    return reply;

}
