#pragma once

#include "main.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

// Set up TLS structure
void tls_setup(struct client_options *);
