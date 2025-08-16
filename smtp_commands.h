#pragma once

#include "main.h"

// Start TLS communications
int start_tls(const struct client_options *, struct envelope *);

int ehlo(const struct client_options *, struct envelope *);

int send_mail_and_rcpt(const struct client_options *options,
                       struct envelope *envelope);

int send_data(const struct client_options *options, struct envelope *envelope);
