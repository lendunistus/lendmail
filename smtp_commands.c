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
    for (char *i = strstr(msg + 4, "250"); i != NULL; i = strstr(i, "250")) {
        // Skip over response code and separator
        i += 4;
        if (strncmp(i, "PIPELINING", 10) == 0) {
            envelope->pipelining = 1;
        } else if (strncmp(i, "STARTTLS", 8) == 0) {
            envelope->tls_possible = 1;
        } else if (strncmp(i, "SIZE", 4) == 0) {
            // Get to SIZE argument
            i += 5;
            envelope->max_size = strtoul(i, NULL, 10);
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
            if (*(*buf + i) == '-') {
                break;
            } else if (*(*buf + i) == '\n') {
                last_line = 1;
                break;
            }
        }
    }

    // We need the null terminator for parsing later
    *(*buf + bytes_got) = '\0';
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

// Add "MAIL FROM:<sender address>\r\n" to provided buffer. Returns number
// of bytes added to buffer
static size_t append_mail_from(const struct client_options *options, char **buf,
                               size_t *buflen) {
    // "MAIL FROM:<" and ">\r\n" is 14 chars
    size_t msglen = strlen(options->sender) + 14;
    if (*buflen < msglen) {
        char *new_ptr = realloc(buf, msglen);
        if (new_ptr == NULL) {
            printf("generate_mail_from: alloc failed");
            exit(1);
        }
        *buflen = msglen;
        *buf = new_ptr;
    }

    memcpy(*buf, "MAIL FROM:<", 11);
    memcpy(*buf + 11, options->sender, msglen - 14);
    memcpy(*buf + msglen - 3, ">\r\n", 3);

    return msglen;
}

// Append "RCPT TO:<recipient address>\r\n" to buffer at provided index,
// resizing buffer if needed. Returns number of bytes added to buffer
static size_t append_rcpt_to(const struct client_options *options, char **buf,
                             size_t *buflen, size_t append_idx,
                             struct recipient *recipient) {
    size_t msglen = 12 + strlen(recipient->address);
    if (*buflen < msglen + append_idx) {
        char *new_ptr = realloc(buf, msglen + append_idx);
        if (new_ptr == NULL) {
            printf("generate_mail_from: alloc failed");
            exit(1);
        }
        *buflen = msglen;
        *buf = new_ptr;
    }

    memcpy(*buf + append_idx, "RCPT TO:<", 9);
    memcpy(*buf + append_idx + 9, recipient->address, msglen - 12);
    memcpy(*buf + append_idx + msglen - 3, ">\r\n", 3);

    return msglen;
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

// Send EHLO command and parse response to find supported extensions
int ehlo(const struct client_options *options, struct envelope *envelope) {
    if (send_ehlo(envelope, options->domain) != 0) {
        printf("EHLO failed\n");
        return -1;
    }
    recv_ehlo(envelope, &envelope->buf, &envelope->buflen);
    parse_ehlo_list(envelope, envelope->buf, envelope->buflen);
    memset(envelope->buf, 0, envelope->buflen);

    return 0;
}

// Send "MAIL TO" and "RCPT TO" commands to server in one go. To be used if
// server reports pipelining support (RFC 2920) in EHLO
int send_mail_and_rcpt(const struct client_options *options,
                       struct envelope *envelope) {
    size_t msglen = 0;

    msglen += append_mail_from(options, &envelope->buf, &envelope->buflen);
    // One RCPT TO command per recipient
    for (size_t i = 0; i < envelope->recipients_no; i++) {
        msglen += append_rcpt_to(options, &envelope->buf, &envelope->buflen,
                                 msglen, &envelope->recipients[i]);
    }

    if (sendall(envelope, envelope->buf, &msglen) < 0) {
        printf("send_mail_and_rcpt: send failed");
        exit(1);
    }

    // Receive response(s)
    size_t response_len = recvall(envelope, envelope->buf, envelope->buflen);
    // TODO: Look at response codes

    return 0;
}

int send_data(const struct client_options *options, struct envelope *envelope) {
    size_t msglen = 6;
    if (sendall(envelope, "DATA\r\n", &msglen) < 0) {
        printf("send_data: send failed");
        exit(1);
    }

    recvall(envelope, envelope->buf, envelope->buflen);
    char code[4] = {0};
    memcpy(code, envelope->buf, 3);
    if (strcmp(code, "250")) {
        printf("wrong response code: %s", code);
        exit(1);
    }

    size_t bytes_got = 0;
    while ((bytes_got = fread(envelope->buf, 1, 1024, options->message)) != 0) {
        sendall(envelope, envelope->buf, &bytes_got);
    }

    size_t msg_len = 5;
    sendall(envelope, "\r\n.\r\n", &msg_len);

    msg_len = recvall(envelope, envelope->buf, envelope->buflen);

    msg_len = recvall(envelope, envelope->buf, envelope->buflen);
    envelope->buf[msglen] = '\0';
    printf("%s", envelope->buf);
    return 0;
}
