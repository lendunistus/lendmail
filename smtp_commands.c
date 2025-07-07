// Functions to send various SMTP commands

#include "main.h"

// Send SMTP EHLO command with supplied domain
int send_ehlo(int sockfd, char *domain) {
  size_t domain_len = strlen(domain);
  char *msg = malloc(7 + domain_len);
  memcpy(msg, "EHLO ", 5);
  memcpy(msg + 5, domain, domain_len);
  memcpy(msg + 5 + domain_len, "\r\n", 2);
  // "EHLO " + CRLF is 7 bytes
  size_t msg_len = domain_len + 7;
  printf("msg_len: %zu", msg_len);
  /* I spent like an hour debuugging why the recv call after
   * an EHLO send was blocking. I was using the domain var
   * here instead of msg. I hate myself*/
  if (sendall(sockfd, msg, &msg_len) != 0) {
    printf("Send failed: sent %zu bytes", msg_len);
    return (-1);
  }
  char sent_msg[15];
  memcpy(sent_msg, msg, 15);
  printf("%s\n", sent_msg);
  if ((*(sent_msg + msg_len - 2) == '\r') &
      (*(sent_msg + msg_len - 1) == '\n')) {
    printf("Ends with CRLF\n");
  }

  free(msg);
  return 0;
}
