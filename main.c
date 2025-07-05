// Hello there!

#include <ares.h>
#include <string.h>

#include "main.h"
#include "smtp_commands.h"

#define BUFSIZE 4096
#define MX_HOSTS_DEFAULT 10
#define CONNECT_TIMEOUT 1500
#define DOMAIN "trumm.eu"

/* Send all bytes in buffer, accounting for partial sends (thanks beej)
 * Returns 0 on success and -1 on failure */
int sendall(int sockfd, char *buf, size_t *buflen) {
  size_t bytes_sent = 0;
  size_t bytesleft = 0;
  int n;

  while (bytes_sent < *buflen) {
    n = send(sockfd, buf + bytes_sent, bytesleft, 0);
    if (n == -1)
      break;
    bytes_sent += n;
    bytesleft -= n;
  }

  *buflen = bytes_sent;
  return n == -1 ? -1 : 0;
}

/* Receives data into buffer until we have a full command
 * (ends with CRLF).
 * Returns amount of received bytes on success, 0 on failure */
int recvall(int sockfd, char *buf, size_t buflen) {
  size_t bytes_got = 0;
  int n;
  char ending[3];

  // Loop until our buffer ends with CRLF (or our buffer fills)
  while (1) {
    n = recv(sockfd, buf + bytes_got, buflen - bytes_got, 0);
    bytes_got += n;
    memcpy(ending, buf + bytes_got - 3, 3);
    // Did recv return an error?
    if (n < 1) {
      printf("Recv: failure");
      return (-1);
      // Did our buffer fill?
    } else if (bytes_got == buflen) {
      printf("Buffer fill");
      return (bytes_got);
      // Does packet end in CRLF?
    } else if (!strcmp(ending, "\r\n")) {
      break;
    }
  }

  return (bytes_got);
}

/* https://stackoverflow.com/a/61960339
 * maybe I should've made this myself. eh */
int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                         socklen_t addrlen, unsigned int timeout_ms) {
  int rc = 0;
  // Set O_NONBLOCK
  int sockfd_flags_before;
  if ((sockfd_flags_before = fcntl(sockfd, F_GETFL, 0) < 0))
    return -1;
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before | O_NONBLOCK) < 0)
    return -1;
  // Start connecting (asynchronously)
  do {
    if (connect(sockfd, addr, addrlen) < 0) {
      // Did connect return an error? If so, we'll fail.
      if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
        rc = -1;
      }
      // Otherwise, we'll wait for it to complete.
      else {
        // Set a deadline timestamp 'timeout' ms from now (needed b/c poll can
        // be interrupted)
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
          rc = -1;
          break;
        }
        struct timespec deadline = {.tv_sec = now.tv_sec,
                                    .tv_nsec =
                                        now.tv_nsec + timeout_ms * 1000000l};
        // Wait for the connection to complete.
        do {
          // Calculate how long until the deadline
          if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            rc = -1;
            break;
          }
          int ms_until_deadline =
              (int)((deadline.tv_sec - now.tv_sec) * 1000l +
                    (deadline.tv_nsec - now.tv_nsec) / 1000000l);
          if (ms_until_deadline < 0) {
            rc = 0;
            break;
          }
          // Wait for connect to complete (or for the timeout deadline)
          struct pollfd pfds[] = {{.fd = sockfd, .events = POLLOUT}};
          rc = poll(pfds, 1, ms_until_deadline);
          // If poll 'succeeded', make sure it *really* succeeded
          if (rc > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (retval == 0)
              errno = error;
            if (error != 0)
              rc = -1;
          }
        }
        // If poll was interrupted, try again.
        while (rc == -1 && errno == EINTR);
        // Did poll timeout? If so, fail.
        if (rc == 0) {
          errno = ETIMEDOUT;
          rc = -1;
        }
      }
    }
  } while (0);
  // Restore original O_NONBLOCK state
  if (fcntl(sockfd, F_SETFL, sockfd_flags_before) < 0)
    return -1;
  // Success
  return rc;
}

/* Callback called by ares_getaddrinfo - get results of addrinfo call and
 * attempt to connect to host */
void initiate_connection(void *arg, int status, int timeouts,
                         struct ares_addrinfo *result) {
  struct client_options *client_options = (struct client_options *)arg;
  struct ares_addrinfo_node *p;
  char ip_addr_str[INET6_ADDRSTRLEN];

  for (p = result->nodes; p != NULL; p = p->ai_next) {
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

    int rc = connect_with_timeout(sockfd, p->ai_addr, p->ai_addrlen,
                                  client_options->init_connect_timeout);
    if (rc != 1) {
      // If we're here, we've timed out. Clean up socket and do loop again
      printf("Failed: %i\n", rc);
      close(sockfd);
    } else {
      client_options->sockfd = sockfd;
      printf("Socket: %i\n", client_options->sockfd);
      break;
    }
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

/* Store hosts as an array of struct mx_hosts, with the pointer + length
 * stored in the struct found_hosts passed as an arg */
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

  ares_library_init(ARES_LIB_INIT_ALL);
  memset(&options, 0, sizeof(options));
  optmask |= ARES_OPT_EVENT_THREAD;
  options.evsys = ARES_EVSYS_DEFAULT;

  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    printf("c-ares init failed: %s \n", ares_strerror(status));
    return (1);
  }

  struct client_options client_options;
  memset(&client_options, 0, sizeof(struct client_options));
  client_options.sockfd = -1;
  client_options.init_connect_timeout = CONNECT_TIMEOUT;
  client_options.domain = DOMAIN;

  struct found_hosts found_hosts = {.hosts_len = MX_HOSTS_DEFAULT,
                                    .hosts = NULL};
  status = ares_query_dnsrec(channel, argv[1], ARES_CLASS_IN, ARES_REC_TYPE_MX,
                             mx_query_cb, &found_hosts, NULL);
  if (status != ARES_SUCCESS) {
    printf("failed to enqueue query: %s\n", ares_strerror(status));
    return (1);
  }

  ares_queue_wait_empty(channel, -1);
  // Sort found hosts based on priority (hosts with lowest priority value are
  // tried first)
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

  char *buf = calloc(1024, sizeof(char));
  int received = recv(client_options.sockfd, buf, 1024, 0);
  if (received < 1) {
    printf("recv: %s\n", strerror(errno));
    return (0);
  }
  printf("%s", buf);
  // Get last two characters + terminator
  char crlf[3] = {0};
  strncpy(crlf, buf + received - 2, 2);
  if (strcmp(crlf, "\r\n") == 0) {
    printf("Ends with CRLF\n");
  }
  send_ehlo(client_options.sockfd, "trumm.eu");
  received = recv(client_options.sockfd, buf, 1024, 0);
  if (received < 1) {
    printf("recv: %s\n", strerror(errno));
    return (0);
  }
  printf("%s", buf);
  free_mx_hosts(&found_hosts);
  free(buf);
  ares_destroy(channel);
  ares_library_cleanup();
  return (0);
}
