#ifndef DHCOMPLY_BUILD_MESSAGE_FUNCTIONS_H
#define DHCOMPLY_BUILD_MESSAGE_FUNCTIONS_H

#include "dhcomplyDHCPv6Functions.h"

dhcpv6_message_t *buildSolicit(config_t *, const char *);
dhcpv6_message_t *buildRequest(dhcpv6_message_t *, config_t *);
dhcpv6_message_t *buildRenew(dhcpv6_message_t *, dhcpv6_message_t *, config_t *);
dhcpv6_message_t *buildRebind(dhcpv6_message_t *, config_t *);
dhcpv6_message_t *buildDecline(dhcpv6_message_t *, config_t *);
dhcpv6_message_t *buildInformationRequest(config_t *, const char *);
dhcpv6_message_t *buildConfirm(config_t *, const char *, uint32_t *, uint32_t *, uint32_t *);
dhcpv6_message_t *buildRelease(config_t *, const char *);

#endif
