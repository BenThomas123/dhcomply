
#ifndef DHCOMPLYMESSAGEFUNCTIONS_H
#define DHCOMPLYMESSAGEFUNCTIONS_H

#include "dhcomplyDHCPv6Functions.h"

// Solicit
dhcpv6_message_t *buildSolicit(config_t *, const char *);
int sendSolicit(dhcpv6_message_t *, int, const char *, uint32_t);

// Advertisement
dhcpv6_message_t *parseAdvertisement(uint8_t *, dhcpv6_message_t *, int);

// Request
dhcpv6_message_t *buildRequest(dhcpv6_message_t *, config_t *);
int sendRequest(dhcpv6_message_t *, int, const char *, uint32_t);

// Reply
dhcpv6_message_t *parseReply(uint8_t *, dhcpv6_message_t *, const char *, int);
dhcpv6_message_t *parseStatelessReply(uint8_t *, dhcpv6_message_t *, const char *, int);

// Renew
dhcpv6_message_t *buildRenew(dhcpv6_message_t *, config_t *);
int sendRenew(dhcpv6_message_t *, int, const char *, uint32_t);

// Rebind
dhcpv6_message_t *buildRebind(dhcpv6_message_t *, config_t *);
int sendRebind(dhcpv6_message_t *, int, const char *, uint32_t);

// Confirm
dhcpv6_message_t *buildConfirm(config_t *);
int sendConfirm(dhcpv6_message_t *, int);

// Decline
dhcpv6_message_t *buildDecline(dhcpv6_message_t *, config_t *);
int sendDecline(dhcpv6_message_t *, int, const char *, uint32_t);

// Release
dhcpv6_message_t *buildRelease(config_t *);
int sendRelease(dhcpv6_message_t *, int);

// Reconfigure
dhcpv6_message_t *buildReconfigure(config_t *);
int sendReconfigure(dhcpv6_message_t *, int);

// Information-Request
dhcpv6_message_t *buildInformationRequest(config_t *, const char *);
int sendInformationRequest(dhcpv6_message_t *, int, const char *, uint32_t);

#endif
