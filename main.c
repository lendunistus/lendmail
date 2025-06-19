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

void mx_query_cb(void *host, ares_status_t status, size_t timeouts,
                 const ares_dns_record_t *dnsrec) {
  int i;

  if (dnsrec == NULL) {
    return;
  }

  printf("MX hosts for %s:\n", (char *)host);
  for (i = 0; i < ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER); i++) {
    const ares_dns_rr_t *rr = NULL;
    rr = ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
    if (ares_dns_rr_get_type(rr) != ARES_REC_TYPE_MX) {
      continue;
    }

    printf("%s\n", ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE));
    printf("MX Priority: %u \n",
           ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE));
  };
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: main [domain_name]");
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

  status = ares_query_dnsrec(channel, argv[1], ARES_CLASS_IN, ARES_REC_TYPE_MX,
                             mx_query_cb, argv[1], NULL);
  if (status != ARES_SUCCESS) {
    printf("failed to enqueue query: %s\n", ares_strerror(status));
    return (1);
  }

  ares_queue_wait_empty(channel, -1);

  ares_destroy(channel);
  ares_library_cleanup();
  return (0);
}
