#pragma once

#include "main.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

SSL_CTX *create_context(void);

void tls_setup(SSL_CTX *, struct envelope *);
