#ifndef DHCOMPLY_PARSE_MESSAGE_FUNCTIONS_H
#define DHCOMPLY_PARSE_MESSAGE_FUNCTIONS_H

#include "dhcomplyDHCPv6Functions.h"

dhcpv6_message_t *parseAdvertisement(uint8_t *, dhcpv6_message_t *, int);
dhcpv6_message_t *parseReply(uint8_t *, dhcpv6_message_t *, const char *, int);
dhcpv6_message_t *parseStatelessReply(uint8_t *, dhcpv6_message_t *, const char *, int);

#endif
