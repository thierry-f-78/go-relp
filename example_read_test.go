// Copyright (c) 2023 Thierry FOURNIER (tfournier@arpalert.org)

package relp_test

import "io"
import "log"
import "net"
import "os"

import "github.com/thierry-f-78/go-relp"

// This is full example using io.ReadCloser interface with RELP library.
func Example_read() {
	var ln net.Listener
	var conn net.Conn
	var err error
	var opts *relp.Options
	var r *relp.Relp

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

	// Use io.ReadCloser interface to copy log from RELP stream to os.Stdout
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		log.Fatal(err.Error())
	}
}
