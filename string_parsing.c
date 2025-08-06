#include "main.h"
#include <ctype.h>

char *get_server_name(char *address) {
    // The part after the rightmost @ in the address is the server name
    char *server_name_ptr = NULL;
    char *p = strstr(address, "@");
    // Step over the '@'
    while (p != NULL) {
        p++;
        server_name_ptr = p;
        p = strstr(p, "@");
    }
    if (server_name_ptr == NULL) {
        printf("Invalid address: %s", address);
        exit(1);
    }
    // Now finding the end of the domain (any character that isn't alphanumeric,
    // '.' or '-')
    for (p = server_name_ptr; *p != '\0'; p++) {
        if (!isalnum(*p) | (*p != '-') | (*p != '.')) {
            break;
        }
    }
    return server_name_ptr;
}
