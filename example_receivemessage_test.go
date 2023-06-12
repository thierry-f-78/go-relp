// Copyright (c) 2023 Thierry FOURNIER (tfournier@arpalert.org)

package relp_test

import "log"
import "net"

import "github.com/thierry-f-78/go-relp"

// This example show full protocol handler. In most cases, this way is not
// interesting.
func Example_receiveMessage() {
	var ln net.Listener
	var conn net.Conn
	var err error
	var opts *relp.Options
	var r *relp.Relp
	var msg *relp.Message
	var out map[string][]interface{}
	var status bool
	var offer []string
	var message string

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
		return
	}

	defer conn.Close()

	// Create RELP from net.Conn
	r, err = relp.NewTcp(conn, opts)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer r.Close()

	// receive first message, wich must it "open"
	msg, err = r.ReceiveMessage()
	if err != nil {
		log.Fatal(err.Error())
	}
	if msg == nil {
		log.Fatal("client close connection")
	}
	if msg.Command != "open" {
		log.Fatal("expect open message")
	}

	// decode offer
	out, err = r.DecodeOffer(msg)
	if err != nil {
		log.Fatal(err.Error())
	}

	// negociate offer
	status, offer, message = r.NegociateOffer(msg, out)

	// Answer offer
	if !status {
		r.AnswerError(msg, message)
		log.Fatal("negociation fail")
	}
	r.AnswerOffer(msg, message, offer)

	// Receive log message loop
	for {

		// receive next message
		msg, err = r.ReceiveMessage()
		if msg == nil {
			log.Fatal("client close connection")
			return
		}

		// process message according with the received command
		switch msg.Command {

		case "syslog":

			// Process log message. Here, just display it
			println(string(msg.Data))

			// Acknoledge message
			err = r.AnswerOk(msg)
			if err != nil {
				log.Fatal(err.Error())
			}

		case "close":

			// process connection close
			r.AnswerOk(msg)
			log.Fatal("client close connection")

		default:
			// unknown message
			log.Fatalf("unknown command %q", msg.Command)
		}
	}
}
