// Functions that set up OpenSSL contexts and stuff
// https://github.com/openssl/openssl/tree/master/demos/sslecho

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>

#include "main.h"
#include "tls_setup.h"

static SSL_CTX *create_context(void) {
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    printf("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return (ctx);
}

void configure_client_context(SSL_CTX *ctx) {
  // Abort handshake if cert verification fails
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  // Use default system certificate store
  if (!SSL_CTX_set_default_verify_paths(ctx)) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  };
}

void tls_setup(struct client_options *options) {
  // Set up SSL structure
  SSL_CTX *ssl_ctx = create_context();
  configure_client_context(ssl_ctx);
  options->ssl = SSL_new(ssl_ctx);

  if (!SSL_set_fd(options->ssl, options->sockfd)) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (!SSL_set1_host(options->ssl, options->server_name)) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}
