#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <cjson/cJSON.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define MAC_ADDRESS_LENGTH 6

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef __uint128_t uint128_t;

void valid_file_pointer(FILE *);
void valid_memory_allocation(void *);
void valid_socket(int);
int get_mac_address(const char *, uint8_t[6]);

void randomize();
void create_config_file();
void create_IA_file();
void init_dhcomply();

char *substring(const char *, size_t, size_t);
char *trim(char *);
void to_uppercase(char *);
int uint128_to_ipv6_str(__uint128_t, char *, size_t);
char *append_ipv6_address_if_unique(const char *, const char *);
char *format_ipv6_prefix(uint8_t prefix_len, uint128_t prefix);

int max(int, int);
int min(int, int);


void userLog (const char *);
void errorLog (const char *);
void debugLog (const char *);
