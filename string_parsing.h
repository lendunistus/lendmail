#pragma once

// Take null-terminated string in format "user@domain" and extract domain
// part
char *get_server_name(char *);
