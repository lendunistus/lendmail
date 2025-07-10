#pragma once

#include "main.h"
// Send SMTP EHLO command
int send_ehlo(struct client_options *);

// Start TLS communications
int start_tls(struct client_options *);
