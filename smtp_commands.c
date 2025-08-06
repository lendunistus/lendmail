// Functions to send various SMTP commands

#include "smtp_commands.h"
#include "main.h"
#include "tls_setup.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

// Parse opening EHLO message and store things in provided envelope
static void parse_ehlo_list(struct envelope *envelope, char *msg,
                            size_t msglen) {
    // First line of EHLO is a welcome message, skipping over it
    char *i = strstr(msg + 4, "250");

    for (i; i != NULL; i = strstr(msg, "250")) {
        // Skip over response code and separator
        i += 4;
        if (strncmp(msg, "PIPELINING", 10) == 0) {
            envelope->pipelining = 1;
        } else if (strncmp(msg, "STARTTLS", 8) == 0) {
            envelope->tls_possible = 1;
        } else if (strncmp(msg, "SIZE", 4) == 0) {
            // Get to SIZE argument
            i += 5;
            envelope->max_size = strtol(i, NULL, 10);
        }
        // EHLO values that we don't know about are ignored
    }
}

int parse_response_code(char *response);

// Receive EHLO info message
static int recv_ehlo(struct envelope *envelope, char **buf, size_t *bufsize) {
    size_t bytes_got = 0;
    // Bool used to end while loop when we're on the last line
    char last_line = 0;

    while (!last_line) {
        bytes_got += recvall(envelope, *buf + bytes_got, *bufsize - bytes_got);
        // Did we reach our buffer size?
        if (bytes_got == *bufsize) {
            // Resize so we can fit the message
            char *new_buf = realloc(*buf, *bufsize * 2);
            // Did our alloc fail?
            if (!new_buf) {
                printf("recv_ehlo: alloc fail\n");
                exit(-1);
            }
            *bufsize *= 2;
            *buf = new_buf;
            continue;
        }
        /* Go through response until we find either \n (we're at the last line)
         * or '-'' (we're not at the last line) */
        for (size_t i = bytes_got - 1; i != 0; i--) {
            if (*buf[i] == '-') {
                break;
            } else if (*buf[i] == '\n') {
                last_line = 1;
                break;
            }
        }
    }

    // Size of message + null terminator
    char *final_buf = realloc(*buf, bytes_got + 1);
    if (!final_buf) {
        printf("recv_ehlo: final alloc fail\n");
        exit(-1);
    }
    // We need the null terminator for parsing later
    final_buf[bytes_got] = '\0';
    *buf = final_buf;
    *bufsize = bytes_got;
    return 0;
}

// Send SMTP EHLO command with supplied domain
static int send_ehlo(struct envelope *envelope, char *domain) {
    size_t domain_len = strlen(domain);
    char *msg = malloc(7 + domain_len);
    memcpy(msg, "EHLO ", 5);
    memcpy(msg + 5, domain, domain_len);
    memcpy(msg + 5 + domain_len, "\r\n", 2);
    // "EHLO " + CRLF is 7 bytes
    size_t msg_len = domain_len + 7;
    /* I spent like an hour debugging why the recv call after
     * an EHLO send was blocking. I was using the domain var
     * here instead of msg. I hate myself*/
    if (sendall(envelope, msg, &msg_len) != 0) {
        printf("Send failed: sent %zu bytes\n", msg_len);
        exit(-1);
    }
    if ((*(msg + msg_len - 2) == '\r') & (*(msg + msg_len - 1) == '\n')) {
        printf("Ends with CRLF\n");
    }

    free(msg);
    return 0;
}

int start_tls(const struct client_options *options, struct envelope *envelope) {
    char msg[] = "STARTTLS\r\n";
    size_t msg_len = sizeof msg - 1;
    if (sendall(envelope, msg, &msg_len) != 0) {
        printf("Send failed: sent %zu bytes\n", msg_len);
        exit(-1);
    }

    // Receive TLS response and check code
    char buf[512];
    recvall(envelope, buf, 512);
    char response_code[4] = {0};
    memcpy(response_code, buf, 3);
    if (strcmp(response_code, "220")) {
        printf("Wrong response code: %s\n", response_code);
        return -1;
    }

    tls_setup(options->ssl_ctx, envelope);
    if (SSL_connect(envelope->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

int ehlo(const struct client_options *options, struct envelope *envelope) {
    if (send_ehlo(envelope, options->domain) != 0) {
        printf("EHLO failed");
        return -1;
    }
    recv_ehlo(envelope, &envelope->buf, &envelope->buflen);
    parse_ehlo_list(envelope, envelope->buf, envelope->buflen);

    return 0;
}
