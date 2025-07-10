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

// Stores misc information about client that may need to be passed to functions
struct client_options {
  int init_connect_timeout; // Amount of time in ms to wait to connect to server
  int sockfd;               // Socket we're using to connect to server
  char *domain;             // Our domain (to be reported in EHLO)
  char *server_name;        // Name of server we're connecting to
  SSL *ssl;
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

int sendall(struct client_options *, char *, size_t *);

int recvall(struct client_options *, char *, size_t);

int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen, unsigned int timeout_ms);

void free_mx_hosts(struct found_hosts *found_hosts);
