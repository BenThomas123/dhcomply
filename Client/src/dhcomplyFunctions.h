#include "dhcomplyStandardLibrary.h"

// Retransmission constants
/* ================================================= */
#define SOLICIT_RETRANS_COUNT 14
#define REQUEST_RETRANS_COUNT 10
#define RENEW_RETRANS_COUNT   10
#define REBIND_RETRANS_COUNT  10
#define RELEASE_RETRANS_COUNT  4
#define CONFIRM_RETRANS_COUNT  4
#define DECLINE_RETRANS_COUNT  4

static const uint32_t lower_solicit[] = {
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

static const uint32_t upper_solicit[] = {
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

static const uint32_t lower_request[] = {
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

static const uint32_t upper_request[] = {
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

static const uint32_t renew_lower[] = {
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

static const uint32_t renew_upper[] = {
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

static const uint32_t rebind_lower[] = {
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

static const uint32_t rebind_upper[] = {
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

static const uint32_t release_lower[] = {
    900,
    1710,
    3250,
    6170
};

static const uint32_t release_upper[] = {
    1100,
    2310,
    4850,
    10190
};

static const uint32_t confirm_lower[] = {
    900,
    1710,
    3250,
    3600
};

static const uint32_t confirm_upper[] = {
    1100,
    2310,
    4400,
    4400
};

static const uint32_t decline_lower[] = {
    900,
    1710,
    3250,
    6170
};

static const uint32_t decline_upper[] = {
    1100,
    2310,
    4850,
    10190
};
/* ================================================= */


// message type constants
/* =========================================== */
#define SOLICIT_MESSAGE_TYPE               1
#define ADVERTISE_MESSAGE_TYPE             2
#define REQUEST_MESSAGE_TYPE               3
#define CONFIRM_MESSAGE_TYPE               4
#define RENEW_MESSAGE_TYPE                 5
#define REBIND_MESSAGE_TYPE                6
#define REPLY_MESSAGE_TYPE                 7
#define RELEASE_MESSAGE_TYPE               8
#define DECLINE_MESSAGE_TYPE               9
#define RECONFIGURE_MESSAGE_TYPE          10
#define INFORMATION_REQUEST_MESSAGE_TYPE  11
#define RELAY_FORWARD_MESSAGE_TYPE        12
#define RELAY_REPLY_MESSAGE_TYPE          13
/* =========================================== */

// option code constants
/* ========================================== */
#define CLIENT_ID_OPTION_CODE              1
#define SERVER_ID_OPTION_CODE              2
#define IA_NA_OPTION_CODE                  3
#define IA_ADDR_OPTION_CODE                5
#define ORO_OPTION_CODE                    6
#define PREFERENCE_OPTION_CODE             7
#define ELAPSED_TIME_OPTION_CODE           8
#define RELAY_MSG_OPTION_CODE              9
#define AUTH_OPTION_CODE                  11
#define UNICAST_OPTION_CODE               12
#define STATUS_CODE_OPTION_CODE           13
#define RAPID_COMMIT_OPTION_CODE          14
#define USER_CLASS_OPTION_CODE            15
#define VENDOR_CLASS_OPTION_CODE          16
#define VENDOR_OPTS_OPTION_CODE           17
#define INTERFACE_ID_OPTION_CODE          18
#define RECONF_MSG_OPTION_CODE            19
#define RECONF_ACCEPT_OPTION_CODE         20
#define DNS_SERVERS_OPTION_CODE           23
#define DOMAIN_SEARCH_LIST_OPTION_CODE    24
#define IA_PD_OPTION_CODE                 25
#define IAPREFIX_OPTION_CODE              26
#define INFORMATION_REFRESH_OPTION_CODE   32
#define FQDN_OPTION_CODE                  39
#define PD_EXCLUDE_OPTION_CODE            67
#define SOL_MAX_RT_OPTION_CODE            82
#define INF_MAX_RT_OPTION_CODE            83
/* ========================================== */

// port number constants
/* ============================================ */
#define DHCP_CLIENT_PORT                  546
#define DHCP_SERVER_PORT                  547
/*============================================= */

// address constants
/* ================================================== */
#define ALL_DHCP_RELAY_AGENTS_AND_SERVERS "ff02::1:2"
#define ALL_DHCP_SERVERS                  "ff05::1:3"
/* ================================================== */

// status code constants
/* ================================================== */
#define UNSPECFAIL_STATUS_CODE            1
#define NOADDRAVAIL_STATUS_CODE           2
#define NOBINDING_STATUS_CODE             3
#define NOTONLINK_STATUS_CODE             4
#define USEMULTICAST_STATUS_CODE          5
#define NOPREFIXAVAIL_STATUS_CODE         6
/* ================================================== */

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
#define OPTION_REQUEST_OPTION_LINE "send dhcp6.option-request-option."
static const char* ORO[] = {"user-class", "vendor-class", "vendor-opts", 
    "dns-servers",  "domain-search-list", "information-refresh-time",
    "pd-exclude", "sol-max-rt", "inf-max-rt"};
static const uint8_t ORO_code[] = {15, 16, 17, 23, 24, 32, 67, 82, 83}; 
#define MAX_LINE_LEN 150
/* ================================================================================ */

/*
    Miscellaneous constants
*/ 
/* ================================== */
#define MILLISECONDS_IN_SECONDS 1000
#define MAX_PACKET_SIZE 2000
#define ORO_ARRAY_LENGTH 9
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
/* ============================================== */

typedef struct duid_ll {
    uint16_t duid_type;
    uint16_t hw_type;
    uint8_t *mac;
} duid_ll_t;

typedef struct {
    uint16_t option_code;
    uint16_t option_length;
    union {
        struct client_id {
            duid_ll_t duid;
        } client_id_t;
        struct server_id {
            duid_ll_t duid;
        } server_id_t;
        struct ia_address {
            uint128_t ipv6_address;
            uint64_t preferred_lifetime;
            uint64_t valid_lifetime;
            union dhcpv6_option *ia_address_options;
        } ia_address_t;
        struct ia_na {
            uint32_t iaid;
            uint32_t t1;
            uint32_t t2;
            struct ia_address *addresses;
        } ia_na_t;
        struct option_request {
            uint8_t *option_request;
        } option_request_t;
        struct preference {
            uint8_t preference_value;
        } preference_t;
        struct elapsed_time {
            uint16_t elapsed_time_value;
        } elapsed_time_t;
        struct relay  {
            uint32_t relay_value;
        } relay_t;
        struct authentication {
            uint8_t protocol;
            uint8_t algorithm;
            uint8_t RDM;
            uint64_t replay_detection;
            uint128_t authentication_information;
        } authentication_t;
        struct unicast {
            uint128_t address;
        } unicast_t;
        struct status_code {
            uint16_t status_code;
        } status_code_t;
        struct user_class_option {
            uint128_t user_class_data;
        } user_class_option_t;
        struct vendor_class_option {
            uint32_t enterprise_number;
            uint128_t vendor_class_data;
        } vendor_class_option_t;
        struct vendor_specific_option {
            uint32_t enterprise_number;
            uint128_t vendor_option_data;
        } vendor_specific_option_t;
        struct interface_id {
            uint128_t interface_id_value;
        } interface_id_t;
        struct reconfigure_message {
            uint8_t msg_type;
        } reconfigure_message_t;
        struct ia_prefix {
            uint128_t ipv6_prefix;
            uint64_t preferred_lifetime;
            uint64_t valid_lifetime;
            uint8_t prefix_length;
        } ia_prefix_t;
        struct ia_pd {
            uint32_t iaid;
            uint32_t t1;
            uint32_t t2;
            struct ia_prefix_t *prefixes;
        } ia_pd_t;
        struct information_refresh_time {
            uint32_t information_refresh_time;
        } information_refresh_time_t;
        struct dns_recursive_name_server {
            uint8_t *dns_servers;
        } dns_recursive_name_server_t;
        struct domain_search_list {
            char *search_list;
        } domain_search_list_t;
        struct SOL_MAX_RT {
            uint32_t SOL_MAX_RT_value;
        } SOL_MAX_RT_t;
        struct INF_MAX_RT {
            uint32_t INF_MAX_RT_value;
        } INF_MAX_RT_t;
    };
} dhcpv6_option_t;

typedef struct dhcpv6_message {
    uint8_t message_type;
    uint32_t transaction_id;
    dhcpv6_option_t *option_list;
    uint8_t option_count;
    bool valid;
} dhcpv6_message_t;

typedef struct config {
    uint8_t reconfigure;
    bool rapid_commit;
    uint8_t *oro_list;
    uint8_t oro_list_length;
    bool na;
    bool pd;
} config_t;

typedef struct IANA {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    char * address;
    uint32_t validlifetime;
    uint32_t preferredlifetime;
} IANA_t;

typedef struct IAPD {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    uint128_t prefix;
    uint8_t prefix_length;
    uint32_t validlifetime;
    uint32_t preferredlifetime;
} IAPD_t;

typedef struct stateless {
    char *domain_search_list;
    uint128_t *address_list;
} stateless_t;

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

// Solicit
dhcpv6_message_t *buildSolicit(config_t *, const char *);
int sendSolicit(dhcpv6_message_t *, int, const char *, uint32_t);

// Advertisement
dhcpv6_message_t *parseAdvertisement(uint8_t *, dhcpv6_message_t *, int);

// Request
dhcpv6_message_t *buildRequest(dhcpv6_message_t *, config_t *);
int sendRequest(dhcpv6_message_t *, int , const char *, uint32_t);

// Reply
dhcpv6_message_t *parseReply(uint8_t *, dhcpv6_message_t *, const char *, int);

// Renew
dhcpv6_message_t * buildRenew(dhcpv6_message_t *, config_t *);
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
int sendRelease(dhcpv6_message_t *, int );

// Reconfigure
dhcpv6_message_t *buildReconfigure(config_t *);
int sendReconfigure(dhcpv6_message_t *, int );

// Information-Request
dhcpv6_message_t *buildInformationRequest(config_t *, const char *);
int sendInformationRequest(dhcpv6_message_t *, int, const char *, uint32_t);
