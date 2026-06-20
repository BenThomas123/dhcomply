
#ifndef DHCOMPLY_FUNCTIONS_H
#define DHCOMPLY_FUNCTIONS_H

#include "dhcomplyDHCPv6Constants.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// general functions
config_t *read_config_file(char *);
int check_for_message(int, uint8_t *, int);
int check_for_advertisement(int, uint8_t *, const config_t *);
int check_for_rapid_commit_message(int, uint8_t *, int *);
bool check_dad_failure(const char *interface);
uint8_t get_option_count(uint8_t *, unsigned long int, uint8_t *);
int get_option_index(uint8_t *, unsigned long int, uint8_t);
int writeLease(IANA_t *, IAPD_t *, const char *, const duid_ll_t *, size_t);
void delete_lease_file(char *);
void remove_message_addresses(dhcpv6_message_t *, const char *);
bool is_matching_reply(uint8_t *, int, dhcpv6_message_t *);
void remove_message_addresses(dhcpv6_message_t *, const char *);
uint8_t renewsAllowed(uint32_t);
uint32_t getIAID(char *);
void waitToRetransmit(uint64_t);
uint32_t valid_transaction_id (uint8_t, uint8_t, uint8_t);

#endif // DHCOMPLY_FUNCTIONS_H
