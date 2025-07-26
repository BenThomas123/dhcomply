#include "dhcomplyStandardLibrary.h"

// stdlib addons
void valid_file_pointer(FILE *fp)
{
    if (fp == NULL)
    {
        perror("Invalid file pointer, make sure your config file is in the correct location at /etc/dhcomply.conf\n");
        exit(-1);
    }
}

void valid_memory_allocation(void *allocated_memory)
{
    if (allocated_memory == NULL)
    {
        perror("For some reason memory was not able to be allocated\n");
        exit(-1);
    }
}

void valid_socket(int sockfd) {
    if (sockfd < 0) {
        perror("Invalid Socket\n");
        exit(-1);
    }
}

// string library add ons
char *trim(char *str)
{
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0) // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    // Write new null terminator
    *(end + 1) = '\0';

    return str;
}

char *substring(const char *str, size_t start, size_t len)
{
    size_t str_len = strlen(str);
    if (start >= str_len)
        return "";

    if (start + len > str_len)
    {
        len = str_len - start;
    }

    char *substr = malloc(len + 1);
    if (!substr)
        return NULL;

    memcpy(substr, str + start, len);
    substr[len] = '\0';
    return substr;
}

void to_uppercase(char *str)
{
    while (*str)
    {
        *str = toupper((unsigned char)*str);
        str++;
    }
}

int uint128_to_ipv6_str(__uint128_t value, char *out_str, size_t str_len) {
    struct in6_addr addr;

    for (int i = 0; i < 16; i++) {
        addr.s6_addr[15 - i] = (value >> (i * 8)) & 0xFF;
    }

    if (inet_ntop(AF_INET6, &addr, out_str, str_len) == NULL) {
        return -1;
    }

    return 0;
}

char *append_ipv6_address_if_unique(const char *addr_list, const char *new_addr) {
    if (!addr_list || !new_addr) return 0;

    char *copy = strdup(addr_list);
    if (!copy) return 0;

    char *token = strtok(copy, " ");
    while (token) {
        if (strcmp(token, new_addr) == 0) {
            free(copy);
            return strdup(addr_list);
        }
        token = strtok(0, " ");
    }
    free(copy);

    char *result = malloc(1024);
    if (!result) return 0;

    if (strlen(addr_list) > 0) {
        snprintf(result, 1024, "%s %s", addr_list, new_addr);
    } else {
        snprintf(result, 1024, "%s", new_addr);
    }

    return result;
}

char *format_ipv6_prefix(uint8_t prefix_len, uint128_t prefix) {
    if (prefix_len > 128) return NULL;

    for (int i = 0; i < (prefix_len / 16) + 1; i++) {
        prefix >>= 8;
    }

    char *string = malloc(150);
    snprintf(string, 150, "%08lX::/%hhu", prefix, prefix_len);

    return string;
}

int get_mac_address(const char *iface_name, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    valid_socket(sock);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        exit(-1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_ADDRESS_LENGTH);
    close(sock);
    return 0;
}

void create_config_file() {
    FILE *fp = fopen("/etc/dhcomply.conf", "wx");
    if (fp == NULL) {
        return;
    }
    fclose(fp);
}

void create_IA_file() {
    FILE *fp = fopen("/etc/dhcomplyIA.conf", "wx");
    if (fp == NULL) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);

    if (!size) {
        uint32_t iana = rand() % 0xFFFFFFFF;
        uint32_t iapd = rand() % 0xFFFFFFFF;

        fprintf(fp, "%X\n", iana);
        fprintf(fp, "%X\n", iapd);
    }
    fclose(fp);
}

void init_dhcomply() {
    randomize();
    create_config_file();
    create_IA_file();
}

void randomize () {
    srand(time(NULL));
}

int min (int a, int b) {
    if (a < b) {
        return a;
    }

    return b;
}

int max (int a, int b) {
    if (a > b) {
        return a;
    }

    return b;
}

void UserLog (const char *message) {
    fprintf(stdout, "%s\n", message);
}

void debugLog (const char *message) {
    fprintf(stderr, "%s\n", message);
}

void errorLog (const char *message) {
    fprintf(stderr, "%s\n", message);
}

