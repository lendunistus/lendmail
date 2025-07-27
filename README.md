# lendmail

A command-line SMTP client for sending e-mail, written in C.

CURRENTLY UNFINISHED! Commit 723750b is capable of connecting to specified server, saying hello and starting TLS communications.

To be done:
- Multiple recipients
- Opening and parsing headers of message
- Actually sending message

## Dependencies
- c-ares >= 1.28.0
- OpenSSL >= 3.5 (maybe older works?)
