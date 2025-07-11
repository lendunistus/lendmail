// Functions to send various SMTP commands

#include "smtp_commands.h"
#include "main.h"
#include "tls_setup.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

void parse_ehlo_list(struct client_options *options, char *msg, size_t msglen) {}

int parse_response_code(char *response);

// Send SMTP EHLO command with supplied domain
int send_ehlo(struct client_options *options) {
  size_t domain_len = strlen(options->domain);
  char *msg = malloc(7 + domain_len);
  memcpy(msg, "EHLO ", 5);
  memcpy(msg + 5, options->domain, domain_len);
  memcpy(msg + 5 + domain_len, "\r\n", 2);
  // "EHLO " + CRLF is 7 bytes
  size_t msg_len = domain_len + 7;
  /* I spent like an hour debugging why the recv call after
   * an EHLO send was blocking. I was using the domain var
   * here instead of msg. I hate myself*/
  if (sendall(options, msg, &msg_len) != 0) {
    printf("Send failed: sent %zu bytes", msg_len);
    exit(-1);
  }
  if ((*(msg + msg_len - 2) == '\r') & (*(msg + msg_len - 1) == '\n')) {
    printf("Ends with CRLF\n");
  }

  free(msg);
  return 0;
}

int start_tls(struct client_options *options) {
  char msg[] = "STARTTLS\r\n";
  size_t msg_len = sizeof msg - 1;
  if (sendall(options, msg, &msg_len) != 0) {
    printf("Send failed: sent %zu bytes", msg_len);
    exit(-1);
  }

  // Receive TLS response and check code
  char buf[512];
  recvall(options, buf, 512);
  char response_code[4] = {0};
  memcpy(response_code, buf, 3);
  if (strcmp(response_code, "220")) {
    printf("Wrong response code: %s", response_code);
    return -1;
  }

  tls_setup(options);
  if (SSL_connect(options->ssl) != 1) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}
