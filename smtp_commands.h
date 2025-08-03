#pragma once

#include "main.h"

// Start TLS communications
int start_tls(const struct client_options *, struct envelope *);

int ehlo(const struct client_options *, struct envelope *);
