#pragma once

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Holds address and BCC status of recipient
struct recipient {
    char *address; // Null terminated string in format "user@domain"
    unsigned char bcc : 1;
};

/* Stores information about server that is currently being connected to. One
 * envelope is made per server */
struct envelope {
    char *buf; // Buffer used for incoming & outgoing comms with server
    size_t buflen;
    int sockfd;           // Socket used to connect to server
    unsigned int timeout; // Timeout in ms
    char *server_name;    // Name of server
    struct recipient *recipients;
    size_t recipients_no;
    SSL *ssl;
    // A series of flags that are set via output from EHLO
    unsigned char tls_possible : 1;
    unsigned char pipelining : 1;
    unsigned long max_size;
};

// Stores misc information about client that may need to be passed to functions
struct client_options {
    int timeout;  // Timeout in ms
    char *domain; // Our domain (to be reported in EHLO)
    char *sender; // Sender address as a string
    SSL_CTX *ssl_ctx;
    struct envelope *envelopes; // Servers we're sending our email to
    size_t envelopes_no;
    FILE *message;
};

struct mx_host {
    size_t priority;
    char *name;
};

/* The ares query callback only takes one user arg so I guess we're making a
 * struct */
struct found_hosts {
    size_t hosts_len;
    struct mx_host *hosts;
};

int sendall(struct envelope *, char *, size_t *);

int recvall(struct envelope *, char *, size_t);

int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen, unsigned int timeout_ms);

void free_mx_hosts(struct found_hosts *found_hosts);
