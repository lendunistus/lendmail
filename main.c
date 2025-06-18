// Hello there!

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <bits/types/res_state.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define BUFSIZE 4096

int main(int argc, char **argv) {
  printf("Hello world!\n");
  struct __res_state state;
  if (res_init() < 0) {
    return (1);
  };
  unsigned char buf[BUFSIZE];
  const char *domain_name = "trumm.eu";
  if (res_query(domain_name, C_IN, T_MX, buf, BUFSIZE) < 0) {
    fprintf(stderr, "res_nsearch: %s \n", strerror(errno));
    return (1);
  };
  printf("%s \n", buf);
#if 0
  ns_msg handle;
  if (ns_initparse(buf, NS_PACKETSZ, &handle) < 0) {
    fprintf(stderr, "ns_initparse: %s \n", strerror(errno));
    return (1);
  };
  free(buf);

  ns_rr response;
  char *uncompressed = calloc(MAXDNAME, sizeof(char));
  u_int16_t count = ns_msg_count(handle, ns_s_an);
  printf("msg count: %i \n", count);
  for (int i = 0; i < count; i++) {
    if (ns_parserr(&handle, ns_s_an, i, &response) < 0) {
      fprintf(stderr, "ns_parserr: %s \n", strerror(errno));
      return (1);
    };
    if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
                           ns_rr_rdata(response), uncompressed, MAXDNAME) < 0) {
      fprintf(stderr, "ns_name_uncompress failed! \n");
      return (1);
    };
    printf("%s", uncompressed);
  }
#endif
}
