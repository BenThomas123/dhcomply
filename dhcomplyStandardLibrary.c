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

int bind_dhcpv6_client_socket(int sockfd) {
    struct sockaddr_in6 client_addr = {0};
    client_addr.sin6_family = AF_INET6;
    client_addr.sin6_port = htons(546);  // DHCP client port
    client_addr.sin6_addr = in6addr_any; // all local interfaces

    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Unable to bind");
        exit(-1);
    }

    return 0;
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
