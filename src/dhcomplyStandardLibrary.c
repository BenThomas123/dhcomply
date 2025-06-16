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

void randomize () {
    srand(time(NULL));
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