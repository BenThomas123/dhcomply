#ifndef DHCOMPLYCONSTANTS_H
#define DHCOMPLYCONSTANTS_H

#include "dhcomplyRetransmissionDHCPv6Constants.h"
#include "dhcomplyDHCPv6Structures.h"

// message type constants
/* =========================================== */
#define SOLICIT_MESSAGE_TYPE 1
#define ADVERTISE_MESSAGE_TYPE 2
#define REQUEST_MESSAGE_TYPE 3
#define CONFIRM_MESSAGE_TYPE 4
#define RENEW_MESSAGE_TYPE 5
#define REBIND_MESSAGE_TYPE 6
#define REPLY_MESSAGE_TYPE 7
#define RELEASE_MESSAGE_TYPE 8
#define DECLINE_MESSAGE_TYPE 9
#define RECONFIGURE_MESSAGE_TYPE 10
#define INFORMATION_REQUEST_MESSAGE_TYPE 11
#define RELAY_FORWARD_MESSAGE_TYPE 12
#define RELAY_REPLY_MESSAGE_TYPE 13
/* =========================================== */

// option code constants
/* ========================================== */
#define CLIENT_ID_OPTION_CODE 1
#define SERVER_ID_OPTION_CODE 2
#define IA_NA_OPTION_CODE 3
#define IA_ADDR_OPTION_CODE 5
#define ORO_OPTION_CODE 6
#define PREFERENCE_OPTION_CODE 7
#define ELAPSED_TIME_OPTION_CODE 8
#define RELAY_MSG_OPTION_CODE 9
#define AUTH_OPTION_CODE 11
#define UNICAST_OPTION_CODE 12
#define STATUS_CODE_OPTION_CODE 13
#define RAPID_COMMIT_OPTION_CODE 14
#define USER_CLASS_OPTION_CODE 15
#define VENDOR_CLASS_OPTION_CODE 16
#define VENDOR_OPTS_OPTION_CODE 17
#define INTERFACE_ID_OPTION_CODE 18
#define RECONF_MSG_OPTION_CODE 19
#define RECONF_ACCEPT_OPTION_CODE 20
#define DNS_SERVERS_OPTION_CODE 23
#define DOMAIN_SEARCH_LIST_OPTION_CODE 24
#define IA_PD_OPTION_CODE 25
#define IAPREFIX_OPTION_CODE 26
#define INFORMATION_REFRESH_OPTION_CODE 32
#define FQDN_OPTION_CODE 39
#define PD_EXCLUDE_OPTION_CODE 67
#define SOL_MAX_RT_OPTION_CODE 82
#define INF_MAX_RT_OPTION_CODE 83
/* ========================================== */

// port number constants
/* ============================================ */
#define DHCP_CLIENT_PORT 546
#define DHCP_SERVER_PORT 547
/*============================================= */

// address constants
/* ================================================== */
#define ALL_DHCP_RELAY_AGENTS_AND_SERVERS "ff02::1:2"
#define ALL_DHCP_SERVERS "ff05::1:3"
/* ================================================== */

// status code constants
/* ================================================== */
#define UNSPECFAIL_STATUS_CODE 1
#define NOADDRAVAIL_STATUS_CODE 2
#define NOBINDING_STATUS_CODE 3
#define NOTONLINK_STATUS_CODE 4
#define USEMULTICAST_STATUS_CODE 5
#define NOPREFIXAVAIL_STATUS_CODE 6
/* ================================================== */

#endif //DHCOMPLYCONSTANTS_H
