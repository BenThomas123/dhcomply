#ifndef DHCOMPLYRETRANSMISSIONDHCPV6CONSTANTS_H
#define DHCOMPLYRETRANSMISSIONDHCPV6CONSTANTS_H

#include "dhcomplyStandardLibrary.h"

// Retransmission constants
/* ================================================= */
#define SOLICIT_RETRANS_COUNT 14
#define INFO_REQUEST_RETRANS_COUNT 14
#define REQUEST_RETRANS_COUNT 10
#define RENEW_RETRANS_COUNT 10
#define REBIND_RETRANS_COUNT 10
#define RELEASE_RETRANS_COUNT 4
#define CONFIRM_RETRANS_COUNT 4
#define DECLINE_RETRANS_COUNT 4

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
    3240000};

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
    3960000};

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
    27000};

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
    33000};

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
    540000};

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
    660000};

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
    540000};

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
    660000};

static const uint32_t release_lower[] = {
    900,
    1710,
    3250,
    6170};

static const uint32_t release_upper[] = {
    1100,
    2310,
    4850,
    10190};

static const uint32_t confirm_lower[] = {
    900,
    1710,
    3250,
    3600};

static const uint32_t confirm_upper[] = {
    1100,
    2310,
    4400,
    4400};

static const uint32_t decline_lower[] = {
    900,
    1710,
    3250,
    6170};

static const uint32_t decline_upper[] = {
    1100,
    2310,
    4850,
    10190};
/* ================================================= */

#endif
