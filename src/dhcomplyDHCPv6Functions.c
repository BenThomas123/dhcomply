#include "dhcomplyDHCPv6Functions.h"
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

config_t *read_config_file(char *iaString) {
    config_t *config_file = malloc(sizeof(config_t));
    valid_memory_allocation(config_file);

    config_file->rapid_commit = false;
    config_file->reconfigure = 0;
    config_file->oro_list = NULL;
    config_file->oro_list_length = 0;
    config_file->na = false;
    config_file->pd = false;
	config_file->t1 = 0;
	config_file->t2 = 0;
    bool oppositeMaxRTRequest = false;

    FILE *cfp = fopen(CONFIG_FILE_PATH, "r");
    valid_file_pointer(cfp);

    char line[MAX_LINE_LEN];

    config_file->oro_list = (uint8_t *)calloc(ORO_MAX_REQUESTED_OPTIONS, sizeof(uint8_t));
    valid_memory_allocation(config_file->oro_list);

    while (fgets(line, sizeof(line), cfp)) {
        trim(line);

        if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_RENEW, line)) {
            config_file->reconfigure = 5;
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_REBIND, line)) {
            config_file->reconfigure = 6;
        }
        else if (!strcmp(RECONFIGURE_CONFIG_FILE_LINE_INFO_REQ, line)) {
            config_file->reconfigure = 7;
        }
        else if (!strcmp(RAPID_COMMIT_LINE, line)) {
            config_file->rapid_commit = true;
        } else if (!strcmp(substring(line, 0, strlen(T1_CONFIG_FILE_LINE)), T1_CONFIG_FILE_LINE)) {
			config_file->t1 = strtol(substring_to_end(line, strlen(T1_CONFIG_FILE_LINE)), NULL, 10);
		} else if (!strcmp(substring(line, 0, strlen(T2_CONFIG_FILE_LINE)), T2_CONFIG_FILE_LINE)) {
			config_file->t2 = strtol(substring_to_end(line, strlen(T2_CONFIG_FILE_LINE)), NULL, 10);
		} else if (!strcmp(iaString, STATELESS_STRING) && !strcmp(line, ORO[ORO_ARRAY_LENGTH])) {
            oppositeMaxRTRequest = true;
        } else if (strcmp(iaString, STATELESS_STRING) && !strcmp(line, ORO[ORO_ARRAY_LENGTH + 1])) {
            oppositeMaxRTRequest = true;
        }

        for (int i = 0; i < ORO_ARRAY_LENGTH; i++) {
            if (!strcmp(line, ORO[i])) {
                config_file->oro_list[config_file->oro_list_length++] = ORO_code[i];
            }
        }
    }

    fclose(cfp);

    if (!strcmp(iaString, IA_BOTH_STRING)) {
        config_file->na = true;
        config_file->pd = true;
    } else if (!strcmp(iaString, IAPD_STRING)) {
        config_file->pd = true;
        config_file->na = false;
    } else if (!strcmp(iaString, IANA_STRING)) {
        config_file->na = true;
        config_file->pd = false;
    } else if (!strcmp(iaString, STATELESS_STRING)) {
        config_file->na = false;
        config_file->pd = false;
    }

	if (!strcmp(iaString, STATELESS_STRING)) {
		config_file->oro_list[config_file->oro_list_length++] = INF_MAX_RT_OPTION_CODE;
        if (oppositeMaxRTRequest) {
            config_file->oro_list[config_file->oro_list_length++] = SOL_MAX_RT_OPTION_CODE;
        }
	} else {
		config_file->oro_list[config_file->oro_list_length++] = SOL_MAX_RT_OPTION_CODE;
        if (oppositeMaxRTRequest) {
            config_file->oro_list[config_file->oro_list_length++] = INF_MAX_RT_OPTION_CODE;
        }
	}

	if (config_file->t1 != 0 || config_file->t2 != 0) {
		if (config_file->t1 == 0) { perror("You cannot configure T2 without configuring T1\n"); exit(-1); }
		if (config_file->t2 == 0) { config_file->t2 = config_file->t1 + 5000; }
		if (config_file->t2 <= config_file->t1) {
			perror("You must configure T2 to be greater than T1\n");
			exit(-1);
		}
	}

    return config_file;
}

uint32_t readIANA() {
    FILE *fp = fopen("/etc/dhcomplyIA.conf", "r");
    valid_file_pointer(fp);

	char IA[9];
	if (fgets(IA, sizeof(IA), fp)) {
    	size_t len = strlen(IA);
    	if (len > 0 && IA[len - 1] == '\n') {
        	IA[len - 1] = '\0';
    	}

    	uint32_t num = strtol(IA, NULL, 16);
        fclose(fp);
		return num;
	}

    fclose(fp);

    return 0;
}

uint32_t readIAPD() {
    FILE *fp = fopen("/etc/dhcomplyIA.conf", "r");
    valid_file_pointer(fp);

	char IA[17];
	fgets(IA, sizeof(IA), fp);
	if (fgets(IA, sizeof(IA), fp)) {
        fprintf(stderr, "Reading IAPD from file: %s\n", IA);
        size_t len = strlen(IA);
    	if (len > 0 && IA[len - 1] == '\n') {
        	IA[len - 1] = '\0';
    	}

    	uint32_t num = strtol(IA, NULL, 16);
		fclose(fp);
		return num;
	}

    fclose(fp);

    return 0;
}

int check_for_message(int sockfd, uint8_t *packet, int type) {
    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ready = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready > 0 && FD_ISSET(sockfd, &read_fds)) {
        uint8_t buffer[MAX_PACKET_SIZE];
        ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
        memcpy(packet, buffer, len);
        if (buffer[0] == type) {
            return len;
        }
    }

    return 0;
}

static bool get_check_dad_script_path(char *script_path, size_t script_path_size) {
    char exe_path[PATH_MAX];
    ssize_t exe_path_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_path_len < 0) {
        perror("readlink /proc/self/exe");
        return false;
    }

    exe_path[exe_path_len] = '\0';

    char *last_slash = strrchr(exe_path, '/');
    if (!last_slash) {
        fprintf(stderr, "Unable to determine executable directory from %s\n", exe_path);
        return false;
    }

    *last_slash = '\0';

    int written = snprintf(script_path, script_path_size, "%s/check_dad.sh", exe_path);
    if (written < 0 || (size_t)written >= script_path_size) {
        fprintf(stderr, "check_dad.sh path is too long\n");
        return false;
    }

    return true;
}

bool check_dad_failure(const char *interface) {
    char script_path[PATH_MAX];
    if (!get_check_dad_script_path(script_path, sizeof(script_path))) {
        return false;
    }

    if (access(script_path, R_OK) != 0) {
        fprintf(stderr, "Unable to read DAD check script at %s: %s\n", script_path, strerror(errno));
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return false;
    }

    if (pid == 0) {
        execl("/bin/bash", "bash", script_path, interface, (char *)NULL);
        fprintf(stderr, "Unable to execute DAD check script at %s: %s\n", script_path, strerror(errno));
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return false;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 2) {
            return true;
        } else if (code == 0) {
            return false;
        }
    }

    return false;
}

uint32_t valid_transaction_id (uint8_t byte1, uint8_t byte2, uint8_t byte3) {
    uint32_t trans_id = 0;

    trans_id |= (byte1 << TWO_BYTE_SHIFT);
    trans_id |= (byte2 << ONE_BYTE_SHIFT);
    trans_id |= byte3;

    return trans_id;
}

uint8_t get_option_count(uint8_t *packet, unsigned long int size, uint8_t *iaoption_count) {
    long unsigned int index = 4;
    uint8_t option_count = 0;

    while (index < size) {
        uint16_t option_code = packet[index] << ONE_BYTE_SHIFT;
        option_code |= packet[index + 1];
        if (option_code == IA_NA_OPTION_CODE|| option_code == IA_PD_OPTION_CODE) {
            option_count++;
            (*iaoption_count)++;
        }
        uint16_t option_length = packet[index + 2] << ONE_BYTE_SHIFT;
        option_length |= packet[index + 3];
        option_count++;
        index += (option_length + 4);
    }

    return option_count;
}

int get_option_index(uint8_t *packet, unsigned long int size, uint8_t desired_option_code) {
    long unsigned int index = 4;
    uint8_t option_index = 0;

    while (index < size) {
        uint16_t option_code = packet[index] << ONE_BYTE_SHIFT;
        option_code |= packet[index + 1];
        if (option_code == desired_option_code) return option_index;
        uint16_t option_length = packet[index + 2] << ONE_BYTE_SHIFT;
        option_length |= packet[index + 3];
        index += (option_length + 4);
        option_index++;
    }

    return -1;
}

int writeLease(IANA_t *iana, IAPD_t *iapd, const char *iface_name) {
    cJSON *root = cJSON_CreateObject();
    cJSON *leases = cJSON_AddArrayToObject(root, "leases");

    if (iana) {
        cJSON *iana_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(iana_obj, "type", "IANA");
        char hexstring[11];
        sprintf(hexstring, "%08x", iana->iaid);
        cJSON_AddStringToObject(iana_obj, "iaid", hexstring);
        cJSON_AddNumberToObject(iana_obj, "t1", iana->t1);
        cJSON_AddNumberToObject(iana_obj, "t2", iana->t2);
        cJSON_AddStringToObject(iana_obj, "address", iana->address);
        cJSON_AddNumberToObject(iana_obj, "preferred_lifetime", iana->preferredlifetime);
        cJSON_AddNumberToObject(iana_obj, "valid_lifetime", iana->validlifetime);
        cJSON_AddItemToArray(leases, iana_obj);
    }

    if (iapd) {
        cJSON *iapd_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(iapd_obj, "type", "IAPD");
        char hexstring2[11];
        sprintf(hexstring2, "%08x", iapd->iaid);
        cJSON_AddStringToObject(iapd_obj, "iaid", hexstring2);
        cJSON_AddNumberToObject(iapd_obj, "t1", iapd->t1);
        cJSON_AddNumberToObject(iapd_obj, "t2", iapd->t2);
        char prefix_address[INET6_ADDRSTRLEN];
        char prefix_cidr[INET6_ADDRSTRLEN + 5];
        if (uint128_to_ipv6_str(iapd->prefix, prefix_address, sizeof(prefix_address)) == 0) {
            snprintf(prefix_cidr, sizeof(prefix_cidr), "%s/%u", prefix_address, iapd->prefix_length);
            cJSON_AddStringToObject(iapd_obj, "prefix", prefix_cidr);
        }
        cJSON_AddNumberToObject(iapd_obj, "prefix_length", iapd->prefix_length);
        cJSON_AddNumberToObject(iapd_obj, "preferred_lifetime", iapd->preferredlifetime);
        cJSON_AddNumberToObject(iapd_obj, "valid_lifetime", iapd->validlifetime);
        cJSON_AddItemToArray(leases, iapd_obj);
    }

    char *json_string = cJSON_Print(root);
    if (!json_string) {
        cJSON_Delete(root);
        return -1;
    }

    char filename[strlen(iface_name) + 35];
    snprintf(filename, sizeof(filename), "/var/lib/dhcp/lease_%s.json", iface_name);

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        free(json_string);
        cJSON_Delete(root);
        return -1;
    }
    fputs(json_string, f);
    fclose(f);

    free(json_string);
    cJSON_Delete(root);

    return 0;
}

uint8_t renewsAllowed(uint32_t t1minust2) {
    uint8_t index = 0;
    uint32_t elapsed_time = renew_upper[index] / MILLISECONDS_IN_SECONDS;

    while (elapsed_time < t1minust2 && index < 9) {
        index++;
        elapsed_time += (renew_upper[index] / MILLISECONDS_IN_SECONDS);
    } 

    return index;
}

void waitToRetransmit(uint64_t retrans_time) {
	if (retrans_time >= 1000) {
	    usleep((retrans_time * MICROSECONDS_IN_MILLISECONDS) - MICROSECONDS_IN_SECONDS);
	}
}
