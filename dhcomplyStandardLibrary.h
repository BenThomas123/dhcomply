#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long long uint128_t;

void valid_file_pointer(FILE *);
void valid_memory_allocation(void *);
void valid_socket(int);
char *substring(const char *, size_t, size_t);
char *trim(char *);
void to_uppercase(char *);
