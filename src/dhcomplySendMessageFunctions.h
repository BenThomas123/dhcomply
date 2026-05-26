#ifndef DHCOMPLY_SEND_MESSAGE_FUNCTIONS_H
#define DHCOMPLY_SEND_MESSAGE_FUNCTIONS_H

#include "dhcomplyDHCPv6Functions.h"

int sendSolicit(dhcpv6_message_t *, int, const char *, uint32_t);
int sendRequest(dhcpv6_message_t *, int, const char *, uint32_t);
int sendRenew(dhcpv6_message_t *, int, const char *, uint32_t);
int sendRebind(dhcpv6_message_t *, int, const char *, uint32_t);
int sendDecline(dhcpv6_message_t *, int, const char *, uint32_t);
int sendConfirm(dhcpv6_message_t *, int, const char *, uint32_t);
int sendInformationRequest(dhcpv6_message_t *, int, const char *, uint32_t);

#endif
