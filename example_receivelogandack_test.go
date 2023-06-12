// Copyright (c) 2023 Thierry FOURNIER (tfournier@arpalert.org)

package relp_test

import "log"
import "net"

import "github.com/thierry-f-78/go-relp"

// Show how using a loop of log message with acknoledgments offloaded by the
// RELP library
func Example_receiveLogAndAck() {
	var ln net.Listener
	var conn net.Conn
	var err error
	var opts *relp.Options
	var r *relp.Relp
	var msg string

	// Create and validate options
	opts, err = relp.ValidateOptions(&relp.Options{
		Tls: relp.Opt_tls_disabled,
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
	}

	defer r.Close()

	// Receive log message loop
	for {

		// Receive and acknoledge log message
		msg, err = r.ReceiveLogAndAck()
		if err != nil {
			log.Fatal(err.Error())
		}

		// Process log message. Here, just display it
		println(msg)
	}
}

