#include "dhcomplyFunctions.h"

int main (int argc, char* argv[]) {

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
            sleep(retrans_time / MILLISECONDS_IN_SECONDS);
            firstSol->option_list->elapsed_time_t.elapsed_time_value += retrans_time;
            sendSolicit(firstSol, sockfd);
            i++;
       }
    }
}