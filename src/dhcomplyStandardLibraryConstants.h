#ifndef DHCOMPLYSTANDARDLIBRARYCONSTANTS_H
#define DHCOMPLYSTANDARDLIBRARYCONSTANTS_H

/*
    Miscellaneous constants
*/
/* ================================== */
#define MILLISECONDS_IN_SECONDS 1000
#define MICROSECONDS_IN_MILLISECONDS 1000
#define MICROSECONDS_IN_SECONDS MILLISECONDS_IN_SECONDS * MICROSECONDS_IN_MILLISECONDS
#define MAX_PACKET_SIZE 2000
#define ORO_ARRAY_LENGTH 7
#define ORO_MAX_REQUESTED_OPTIONS ORO_ARRAY_LENGTH + 2
#define OPTION_CODE_LENGTH_IN_ORO 2
#define EMPTY_STRING ""
/* ================================== */

/* ============================================= */
#define ONE_BYTE_SHIFT 8
#define TWO_BYTE_SHIFT 16
#define THREE_BYTE_SHIFT 24
#define FOUR_BYTE_SHIFT 32

#define ONE_BYTE_MASK 0xFF
#define TWO_BYTE_MASK 0xFFFF
#define THREE_BYTE_MASK 0xFFFFFF
#define FOUR_BYTE_MASK 0xFFFFFFFF

#define HEXTETS_IN_IPV6_ADDRESS 16
#define START_POINT_IN_READING_ADDRESS 15
#define MAC_ADDRESS_LENGTH 6
/* ============================================== */

// IA strings
/* ================================================== */
#define IANA_STRING "N"
#define IAPD_STRING "P"
#define IA_BOTH_STRING "NP"
#define STATELESS_STRING "S"
/* ================================================== */

/*
    Config File Constants
*/
/* ================================================================================ */
#define CONFIG_FILE_PATH "/etc/dhcomply.conf"
#define RECONFIGURE_CONFIG_FILE_LINE_RENEW "send dhcp6.reconfigure-accept, 5"
#define RECONFIGURE_CONFIG_FILE_LINE_REBIND "send dhcp6.reconfigure-accept, 6"
#define RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ "send dhcp6.reconfigure-accept, 7"
#define RAPID_COMMIT_LINE "send dhcp6.rapid-commit"
#define FQDN_CONFIG_FILE_LINE "send dhcp6.fully-qualified-domain-name"
#define T1_CONFIG_FILE_LINE "send dhcp6.t1 "
#define T2_CONFIG_FILE_LINE "send dhcp6.t2 "
#define OPTION_REQUEST_OPTION_LINE "send dhcp6.option-request-option."
static const char *ORO[] = {"user-class", "vendor-class", "vendor-opts",
                            "dns-servers", "domain-search-list", "information-refresh-time",
                            "pd-exclude", "sol-max-rt", "inf-max-rt"};
static const uint8_t ORO_code[] = {15, 16, 17, 23, 24, 32, 67};
#define MAX_LINE_LEN 150
/* ================================================================================ */

#endif //DHCOMPLYSTANDARDLIBRARYCONSTANTS_H
