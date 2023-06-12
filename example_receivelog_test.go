// Copyright (c) 2023 Thierry FOURNIER (tfournier@arpalert.org)

package relp_test

import "log"
import "net"

import "github.com/thierry-f-78/go-relp"

// This example show how configure TLS and how to use RELP library making the
// most of the RELP protocol.
func Example_receiveLog() {
	var ln net.Listener
	var conn net.Conn
	var err error
	var opts *relp.Options
	var r *relp.Relp
	var msg *relp.Message

	// Create and validate options
	opts, err = relp.ValidateOptions(&relp.Options{
		Tls: relp.Opt_tls_connection,
		Certificate: "ca/certs/server1.crt",
		PrivateKey: "ca/private/server1.key",
		CACertificate: "ca/certs/myCA.crt",
		Crl: "ca/rootca.crl",
		CnAcl: []relp.Acl{
			relp.Acl{
				Value: "client*",
				Action: relp.Acl_accept,
			},
			relp.Acl{
				Value: "*",
				Action: relp.Acl_reject,
			},
		},
	})
	if err != nil {
		log.Fatalf(err.Error())
	}

	// Create listen connexion
	ln, err = net.Listen("tcp", "0.0.0.0:4150")
	if err != nil {
		log.Fatalf(err.Error())
	}

	// accept connection
	conn, err = ln.Accept()
	if err != nil {
		log.Fatalf(err.Error())
	}

	defer conn.Close()

	// Create RELP from net.Conn
	r, err = relp.NewTcp(conn, opts)
	if err != nil {
		log.Fatal(err.Error())
		return
	}

	defer r.Close()

	// Receive log message loop
	for {

		// Receive log message
		msg, err = r.ReceiveLog()
		if err != nil {
			log.Fatal(err.Error())
		}

		// Process log message. Here, just display it
		println(string(msg.Data))

		// Acknoledge message
		err = r.AnswerOk(msg)
		if err != nil {
			log.Fatal(err.Error())
		}
	}
}

