// Functions to send various SMTP commands

#include "main.h"

// Send SMTP EHLO command with supplied domain
int send_ehlo(int sockfd, char *domain) {
  size_t msg_len = strlen(domain);
  char *msg = malloc(5 + msg_len);
  memcpy(msg, "EHLO ", 5);
  memcpy(msg + 5, domain, msg_len);
  memcpy(msg + 5 + msg_len, "\r\n", 2);
  // "EHLO " + CRLF + terminator is 8 bytes
  msg_len += 8;
  if (sendall(sockfd, domain, &msg_len) != 0) {
    printf("Send failed: sent %zu bytes", msg_len);
    return (-1);
  }
  return 0;
}
