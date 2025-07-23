// Functions that set up OpenSSL contexts and stuff
// https://github.com/openssl/openssl/tree/master/demos/sslecho

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>

#include "main.h"
#include "tls_setup.h"

static void configure_client_context(SSL_CTX *ctx) {
    // Abort handshake if cert verification fails
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Use default system certificate store
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    };
}

// Create configured SSL context
SSL_CTX *create_context(void) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    configure_client_context(ctx);

    return (ctx);
}

// Set up SSL structure for connection with the particular server
void tls_setup(SSL_CTX *ssl_ctx, struct envelope *envelope) {
    // Set up SSL structure
    envelope->ssl = SSL_new(ssl_ctx);

    if (!SSL_set_fd(envelope->ssl, envelope->sockfd)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_set1_host(envelope->ssl, envelope->server_name)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
