// Hello there!

#include <ares.h>
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
  printf("Hello world! \n");
  ares_channel_t *channel = NULL;
  struct ares_options options;
  int optmask = 0;

  ares_library_init(ARES_LIB_INIT_ALL);
  memset(&options, 0, sizeof(options));
  optmask |= ARES_OPT_EVENT_THREAD;
  options.evsys = ARES_EVSYS_DEFAULT;
}
