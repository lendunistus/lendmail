# lendmail

A command-line SMTP client for sending e-mail, written in C.

CURRENTLY UNFINISHED! Current commit is capable of sending email to a server with pipelining support.
Usage:
`[binary] --from [address] --to [comma-separated addresses] [filename]`

```

To be done:

- Opening and parsing headers of message
- Support for non-pipelining servers
- BCC support
- General polish

## Dependencies

- c-ares >= 1.28.0
- OpenSSL >= 3.5 (maybe older works?)
