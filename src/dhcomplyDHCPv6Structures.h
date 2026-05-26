#ifndef DHCOMPLYDHCPV6STRUCTURES_H
#define DHCOMPLYDHCPV6STRUCTURES_H

#include "dhcomplyStandardLibrary.h"

typedef struct duid_ll
{
    uint16_t duid_type;
    uint16_t hw_type;
    uint8_t *mac;
} duid_ll_t;

typedef struct
{
    uint16_t option_code;
    uint16_t option_length;
    union
    {
        struct client_id
        {
            duid_ll_t duid;
        } client_id_t;
        struct server_id
        {
            duid_ll_t duid;
        } server_id_t;
        struct ia_address
        {
            uint128_t ipv6_address;
            uint64_t preferred_lifetime;
            uint64_t valid_lifetime;
            union dhcpv6_option *ia_address_options;
        } ia_address_t;
        struct ia_na
        {
            uint32_t iaid;
            uint32_t t1;
            uint32_t t2;
            struct ia_address *addresses;
        } ia_na_t;
        struct option_request
        {
            uint8_t *option_request;
        } option_request_t;
        struct preference
        {
            uint8_t preference_value;
        } preference_t;
        struct elapsed_time
        {
            uint16_t elapsed_time_value;
        } elapsed_time_t;
        struct relay
        {
            uint32_t relay_value;
        } relay_t;
        struct authentication
        {
            uint8_t protocol;
            uint8_t algorithm;
            uint8_t RDM;
            uint64_t replay_detection;
            uint128_t authentication_information;
        } authentication_t;
        struct unicast
        {
            uint128_t address;
        } unicast_t;
        struct status_code
        {
            uint16_t status_code;
        } status_code_t;
        struct user_class_option
        {
            uint128_t user_class_data;
        } user_class_option_t;
        struct vendor_class_option
        {
            uint32_t enterprise_number;
            uint128_t vendor_class_data;
        } vendor_class_option_t;
        struct vendor_specific_option
        {
            uint32_t enterprise_number;
            uint128_t vendor_option_data;
        } vendor_specific_option_t;
        struct interface_id
        {
            uint128_t interface_id_value;
        } interface_id_t;
        struct reconfigure_message
        {
            uint8_t msg_type;
        } reconfigure_message_t;
        struct ia_prefix
        {
            uint128_t ipv6_prefix;
            uint64_t preferred_lifetime;
            uint64_t valid_lifetime;
            uint8_t prefix_length;
        } ia_prefix_t;
        struct ia_pd
        {
            uint32_t iaid;
            uint32_t t1;
            uint32_t t2;
            struct ia_prefix_t *prefixes;
        } ia_pd_t;
        struct information_refresh_time
        {
            uint32_t information_refresh_time;
        } information_refresh_time_t;
        struct dns_recursive_name_server
        {
            uint8_t *dns_servers;
        } dns_recursive_name_server_t;
        struct domain_search_list
        {
            char *search_list;
        } domain_search_list_t;
        struct SOL_MAX_RT
        {
            uint32_t SOL_MAX_RT_value;
        } SOL_MAX_RT_t;
        struct INF_MAX_RT
        {
            uint32_t INF_MAX_RT_value;
        } INF_MAX_RT_t;
    };
} dhcpv6_option_t;

typedef struct dhcpv6_message
{
    uint8_t message_type;
    uint32_t transaction_id;
    dhcpv6_option_t *option_list;
    uint8_t option_count;
    bool valid;
} dhcpv6_message_t;

typedef struct config
{
    uint8_t reconfigure;
    bool rapid_commit;
    uint8_t *oro_list;
    uint8_t oro_list_length;
    bool na;
    bool pd;
    uint32_t t1;
    uint32_t t2;
    char *ianaIaid;
    char *iapdIaid;
} config_t;

typedef struct IANA
{
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    char *address;
    uint32_t validlifetime;
    uint32_t preferredlifetime;
} IANA_t;

typedef struct IAPD
{
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    uint128_t prefix;
    uint8_t prefix_length;
    uint32_t validlifetime;
    uint32_t preferredlifetime;
} IAPD_t;

typedef struct stateless
{
    char *domain_search_list;
    uint128_t *address_list;
} stateless_t;

#endif //DHCOMPLYDHCPV6STRUCTURES_H
