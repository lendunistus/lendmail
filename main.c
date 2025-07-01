// Hello there!

#include <ares.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFSIZE 4096
#define MX_HOSTS_DEFAULT 10
#define CONNECT_TIMEOUT 1500

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

// Stores misc information about client that may need to be passed to functions
struct client_options {
  int init_connect_timeout; // Amount of time in ms to wait to connect to server
  int sockfd; // Socket we're using to connect to server
};

/* Callback called by ares_getaddrinfo - get results of addrinfo call and
 * attempt to connect to host */
void initiate_connection(void *arg, int status, 
                         int timeouts, struct ares_addrinfo *result) {
  struct client_options *client_options = (struct client_options *)arg;
  struct ares_addrinfo_node *p;
  char ip_addr_str[INET6_ADDRSTRLEN];

  for(p = result->nodes; p != NULL; p = p->ai_next) {
    // Get string representation (thanks beej)
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;
    void *addr;
    if (p->ai_family == AF_INET) {
      ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
    } else {
      ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
    }
    // Get new socket (error checked)
    int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) {
      return;
    }
    
    /* We're using poll() so we can have connect() with a timeout
     * This sets up pollfd array (with one element) and attempts to connect */
    struct pollfd pfds[1];
    pfds[0].fd = sockfd; // Socket we just made
    pfds[0].events = POLLOUT; // Inform if ready to send without blocking
  
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
      printf("connect: %s\n", strerror(errno));
      return;
    }
    if (poll(pfds, 1, client_options->init_connect_timeout) == 1) {
      // If we're here, connection succeeded
      client_options->sockfd = sockfd;
      inet_ntop(p->ai_family, addr, ip_addr_str, INET6_ADDRSTRLEN);
      printf("Successfully connected to %s\n", ip_addr_str);
      break;
    }

    // If we're here, we've timed out. Clean up socket and do loop again
    close(sockfd);
  }
}

/* are my data structures really this awful */
void free_mx_hosts(struct found_hosts *found_hosts) {
  // Free names
  for (size_t i = 0; i < found_hosts->hosts_len; i++) {
    free(found_hosts->hosts[i].name);
  }
  free(found_hosts->hosts);
}

int mx_host_compare(const void *a, const void *b) {
  if (((struct mx_host *)a)->priority < ((struct mx_host *)b)->priority) {
    return (-1);
  } else if (((struct mx_host *)a)->priority >
             ((struct mx_host *)b)->priority) {
    return (1);
  } else {
    return (0);
  }
}

void mx_query_cb(void *arg, ares_status_t status, size_t timeouts,
                 const ares_dns_record_t *dnsrec) {
  size_t i, mx_count = 0;
  // because I don't want to have to cast the pointer every time
  struct found_hosts *found_hosts = arg;
  // Prepare hosts array
  found_hosts->hosts = malloc(sizeof(struct mx_host) * MX_HOSTS_DEFAULT);

  if (dnsrec == NULL) {
    return;
  }

  for (i = 0; i < ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); i++) {
    const ares_dns_rr_t *rr = NULL;
    rr = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
    if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_MX) {
      continue;
    };

    mx_count++;
    printf("hosts_len: %zu, mx_count: %zu\n", found_hosts->hosts_len, mx_count);
    if (mx_count >= found_hosts->hosts_len) {
      found_hosts->hosts =
          realloc(found_hosts->hosts,
                  found_hosts->hosts_len * 2 * sizeof(struct mx_host));
      found_hosts->hosts_len *= 2;
    };
    struct mx_host host = {
        .priority = ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE),
        /* All of the RR memory is freed after exiting from the callback, so
        we have to make a copy */
        .name = strdup(ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE))};
    found_hosts->hosts[mx_count - 1] = host;
  };
  printf("for loop done\n");
  found_hosts->hosts =
      realloc(found_hosts->hosts, mx_count * sizeof(struct mx_host));
  printf("realloc done\n");
  found_hosts->hosts_len = mx_count;
  printf("callback finished\n");
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s [domain_name]\n", argv[0]);
    return (0);
  }

  printf("Hello world! \n");
  ares_channel_t *channel = NULL;
  struct ares_options options;
  int optmask = 0;
  ares_status_t status;

  struct client_options client_options;
  memset(&client_options, 0, sizeof(struct client_options));
  client_options.init_connect_timeout = CONNECT_TIMEOUT;
  client_options.sockfd = -1;

  ares_library_init(ARES_LIB_INIT_ALL);
  memset(&options, 0, sizeof(options));
  optmask |= ARES_OPT_EVENT_THREAD;
  options.evsys = ARES_EVSYS_DEFAULT;

  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    printf("c-ares init failed: %s \n", ares_strerror(status));
    return (1);
  }

  struct found_hosts found_hosts = {.hosts_len = MX_HOSTS_DEFAULT,
                                    .hosts = NULL};
  status = ares_query_dnsrec(channel, argv[1], ARES_CLASS_IN, ARES_REC_TYPE_MX,
                             mx_query_cb, &found_hosts, NULL);
  if (status != ARES_SUCCESS) {
    printf("failed to enqueue query: %s\n", ares_strerror(status));
    return (1);
  }

  ares_queue_wait_empty(channel, -1);
  // Sort found hosts based on priority (hosts with lowest priority value are tried first)
  qsort(found_hosts.hosts, found_hosts.hosts_len, sizeof(struct mx_host),
        mx_host_compare);

  struct ares_addrinfo_hints hints;
  memset(&hints, 0, sizeof(struct ares_addrinfo_hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  for (int i = 0; i < found_hosts.hosts_len; i++) {
    ares_getaddrinfo(channel, found_hosts.hosts[i].name, "smtp", &hints,
                     initiate_connection, &client_options);
    ares_queue_wait_empty(channel, -1);

    // sockfd being default means we couldn't connect
    if (client_options.sockfd != -1) {
      break;
    }
  };

  char *buf = malloc(1024);
  if (recv(client_options.sockfd, buf, 1024, 0) < 1) {
    printf("recv: %s\n", strerror(errno));
    return (0);
  }
  printf("%s", buf);
  free_mx_hosts(&found_hosts);
  ares_destroy(channel);
  ares_library_cleanup();
  return (0);
}
