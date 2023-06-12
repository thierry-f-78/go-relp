[![GoDoc](https://pkg.go.dev/badge/github.com/thierry-f-78/go-relp)](https://pkg.go.dev/github.com/thierry-f-78/go-relp)

RELP Server Library for the GO programming language.
----------------------------------------------------

This package provides RELP server implementation based on
https://github.com/rsyslog/librelp specifications. RELP is great protocol used
to transfer log without loss. It is easy to understand and embed some security
consideration: confidentiality, integrity and authentication using TLS,
loss-proof using RELP.

This library doesn't have any other dependencies than standard Go library.

Library support version 0 (experimental) and 1 of the protocol. Note RHEL8-like
distribution proposes Rsyslog with version 0 of the RELP protocol.

# Known limits

The "starttls" feature is not supported. The RELP C library documentation talk
about this command, but it is not implemented in librelp. In other way, it is
not implemented in any rsyslog. To use TLS, just use RELP over TLS connection.
The Go RELP library embed necessary to handle TLS.

Only server side is implemented. If it have some needs about the client side, we
can consider implement it.

# Network managment overview

The RELP library propose two ways for the network management:

The developper implements full network stack including TLS if it is useful,
he gives only an io.ReadWriter to the library. The caller is responssible to
close all connections.

The developper implement only TCP server, it gives net.Conn To the library
The library manages TLS is required. The caller is reponsible to close tcp
connection.

# Consume logs methods overview

The RELP library propose four ways for the output logs management

The caller implements negociation, he receive all messages and decide responses.
It also do something on negociation. This mode is too complicated and useless.

The caller receive only logs message, he should sent acquirements. This mode
allow to ensure log processing before sending acquirement. for example, the
developper can ensure the log line was writen on disk before aquire the log
line. By this way if the process crash before writing, the log line keep in
client storage.

The caller receive logs as string. The library sent automatically acquirements.
This is usefull to write quick code to receive logs, but you cannot deal with
acquirements.

The library implement io.ReadCloser interface. you can receive logs as stream.
Be prudent with `'\n'`, some logs can contains `'\n'` and other control
character, but `'\n'` is the log separator in []byte stream. The option
StreamEscapeLf replace the control char `'\n'` by two ascii chars `'\\'`, `'n'`.

The library doesn't not implement timeouts because the server never wait for
client.
