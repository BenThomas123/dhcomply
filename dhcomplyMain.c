#include "dhcomplyFunctions.h"

const uint32_t lower_solicit[] = {
    1000,
    1900,
    3610,
    6860,
    13030,
    24760,
    47050,
    89390,
    169840,
    322690,
    613110,
    1164900,
    2213310,
    3240000
};

const uint32_t upper_solicit[] = {
    1100,
    2310,
    4850,
    10190,
    21390,
    44930,
    94340,
    198120,
    416050,
    873710,
    1834790,
    3853050,
    3960000,
    3960000
};

const uint32_t lower_request[] = {
    900,
    1710,
    3250,
    6170,
    11730,
    22280,
    27000,
    27000,
    27000,
    27000
};

const uint32_t upper_request[] = {
    1100,
    2310,
    4850,
    10190,
    21390,
    33000,
    33000,
    33000,
    33000,
    33000
};

const uint32_t renew_lower[] = {
    9000,
    17100,
    32490,
    61730,
    117290,
    222850,
    423410,
    540000,
    540000,
    540000
};

const uint32_t renew_upper[] = {
    11000,
    23100,
    48510,
    101870,
    213930,
    449250,
    660000,
    660000,
    660000,
    660000
};

const uint32_t rebind_lower[] = {
    9000,
    17100,
    32490,
    61730,
    117290,
    222850,
    423410,
    540000,
    540000,
    540000
};

const uint32_t rebind_upper[] = {
    11000,
    23100,
    48510,
    101870,
    213930,
    449250,
    660000,
    660000,
    660000,
    660000
};

const uint32_t release_lower[] = {
    900,
    1710,
    3250,
    6170
};

const uint32_t release_upper[] = {
    1100,
    2310,
    4850,
    10190
};

const uint32_t confirm_lower[] = {
    900,
    1710,
    3250,
    3600
};

const uint32_t confirm_upper[] = {
    1100,
    2310,
    4400,
    4400
};

const uint32_t decline_lower[] = {
    900,
    1710,
    3250,
    6170
};

const uint32_t decline_upper[] = {
    1100,
    2310,
    4850,
    10190
};

int main (int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Invalid arguments");
    }

    bool enabled = true;
    bool waiting_for_adv = true;
    bool waiting_for_lease = true;
    bool waiting_for_rebind = true;
    bool waiting_for_release = true;

    config_t *config_file = read_config_file(argv[1]);
    
    while (enabled) {

       dhcpv6_message_t *firstSol = buildSolicit(config_file);
       int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
       sendSolicit(firstSol, sockfd);
       
       uint8_t i = 0;
       while (waiting_for_adv && i < 13) {
            uint16_t retrans_time = rand() % (upper_solicit[i] - lower_solicit[i]);
            sleep(retrans_time);
            firstSol->option_list->elapsed_time_t.elapsed_time_value += retrans_time;
            sendSolicit(firstSol, sockfd);
            i++;
       }
    }
}