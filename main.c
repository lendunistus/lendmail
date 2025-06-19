// Hello there!

#include <ares.h>
#include <ares_dns_record.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <bits/types/res_state.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define BUFSIZE 4096

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

void mx_query_cb(void *arg, ares_status_t status, size_t timeouts,
                 const ares_dns_record_t *dnsrec) {
  size_t i, mx_count;
  // because I don't want to have to cast the pointer every time
  struct found_hosts *found_hosts = arg;
  // Prepare hosts array
  found_hosts->hosts = malloc(sizeof(struct mx_host));

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
    printf("%u \n",found_hosts->hosts_len);
    if (mx_count >= found_hosts->hosts_len) {
      found_hosts->hosts = realloc(found_hosts->hosts, found_hosts->hosts_len * 2 * sizeof(struct mx_host));
      found_hosts->hosts_len *= 2 * sizeof(struct mx_host);
    };
    struct mx_host host = {
	    .priority = ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE),
	    .name = ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE)
	    };
    found_hosts->hosts[mx_count - 1] = host;
  };
  found_hosts->hosts = realloc(found_hosts->hosts, mx_count);
  found_hosts->hosts_len = mx_count;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: main [domain_name]\n");
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

  struct found_hosts found_hosts = {.hosts_len = 1, .hosts = NULL};
  status = ares_query_dnsrec(channel, argv[1], ARES_CLASS_IN, ARES_REC_TYPE_MX,
                             mx_query_cb, &found_hosts, NULL);
  if (status != ARES_SUCCESS) {
    printf("failed to enqueue query: %s\n", ares_strerror(status));
    return (1);
  }

  ares_queue_wait_empty(channel, -1);

  for (int i = 0; i < found_hosts.hosts_len; i++) {
	  printf("%s", found_hosts.hosts[i].name);
	  };

  ares_destroy(channel);
  ares_library_cleanup();
  return (0);
}
