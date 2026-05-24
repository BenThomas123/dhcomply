
#ifndef DHCOMPLY_FUNCTIONS_H
#define DHCOMPLY_FUNCTIONS_H

#include "dhcomplyDHCPv6Constants.h"

// general functions
config_t *read_config_file(char *);
int check_for_message(int, uint8_t *, int);
bool check_dad_failure(const char *interface);
uint8_t get_option_count(uint8_t *, unsigned long int, uint8_t *);
int get_option_index(uint8_t *, unsigned long int, uint8_t);
int writeLease(IANA_t *, IAPD_t *, const char *);
uint8_t renewsAllowed(uint32_t);
uint32_t readIANA();
uint32_t readIAPD();
void waitToRetransmit(uint64_t);

#endif // DHCOMPLY_FUNCTIONS_H
