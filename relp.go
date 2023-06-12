// Copyright (c) 2023 Thierry FOURNIER (tfournier@arpalert.org)

package relp

import "bytes"
import "crypto/tls"
import "crypto/x509"
import "crypto/x509/pkix"
import "encoding/pem"
import "fmt"
import "io"
import "net"
import "os"
import "path/filepath"
import "strconv"
import "strings"

// TLS configuraiton option: Disable TLS support trought starttls function.
// Note: starttls is not supported. This option will be implemented when RELP
// reference library will support starttls. Even "startls" is not supported, the
// negociation of "startls" command it is. Using this option, "starttls" is not
// announced.
const Opt_tls_disabled = 0

// TLS configuraiton option: Allow starttls command. Note: starttls is not
// supported. This option will be implemented when RELP reference library will
// support starttls. Even "startls" is not supported, the negociation of
// "startls" command it is. Using this option allow the client to use "starttls"
// command. This doesn't work. Do not use.
const Opt_tls_allowed = 1

// TLS configuraiton option: Require starttls command. Note: starttls is not
// supported. This option will be implemented when RELP reference library will
// support starttls. Even "startls" is not supported, the negociation of
// "startls" command it is.
const Opt_tls_required = 2

// TLS configuration option: Enable RELP over TLS at client connection. This
// option disable "starttls". When this connecion mode is activated, the
// configuraiton require setr of certificates throught options "CACertificate",
// "Certificate" and "PrivateKey". At this time only private pki is supported.
// certification chain is not supported. A CRL file can be used with option
// "Crl" and a lot of ACL on certificate Common Name could be configured.
// Note the server require client certificate.
const Opt_tls_connection = 3

// TLS configuration option: This option assume the io.ReadWriter given ensure
// transport security over TLS and disbale "starttls" command.
const Opt_tls_offloading = 4

// ACL configuration: accept connexion
const Acl_accept = 0

// ACL configuration: reject connexion
const Acl_reject = 1

// This struct define ACL. ACL is part of a list which define condition and
// action. Condition is a wildcard match between Value field and client
// certificate CN. If the wildcard match, Action reject or accept is applied
// and the Acl evalution stop.
type Acl struct {
	Value string
	Action int
}

// This struct contains configuration option for the RELP server.
// CACertificate, Certificate and PrivateKey are mandatory if Tls option is
// Opt_tls_connection. The Certificate must be validated by the CACertificate.
// Each incoming TLS client connection must provides certificate signed by CA.
//
// CnAcl is a list of Acl which validates cleint Common Name certificate.
//
// RecvSize is the size of read buffer. Default size is 16384.
//
// StreamEscapeLf is an option which replace all '\n' characters by '\', 'n'.
// this is usefull because in stream mode, the log separator is '\n', but some
// component could log multiline messages, for example backtraces. This escape
// is not strict, because we cannot differentiate modified sequence '\', 'n'
// with original sequence, so the original log cannot be recovered with high
// confidence.
type Options struct {
	Tls int // Opt_tls_*
	CACertificate string // Path to CA file at PEM format
	Certificate string // Path to certificate file at PEM format
	PrivateKey string // Path to private key at PEM format
	Crl string // Path to CRL file at PEM format
	CnAcl []Acl
	RecvSize int
	StreamEscapeLf bool

	tlsConfig *tls.Config
	revocationList *x509.RevocationList
	ca *x509.Certificate
	crt *x509.Certificate
	vrfyOpts x509.VerifyOptions
}

// This struct is used to maintain state of established RELP connection.
// This struct implements interface io.ReadCloser
type Relp struct {
	tcp_fd net.Conn
	tls_fd *tls.Conn
	fd io.ReadWriter
	buffer []byte
	out_buffer []byte
	version int
	open bool
	closed bool
	opts *Options
}

// This struct contains RELP message. Txnr is the unique number od the message
// in the stream. Command is a string containing RELP command. today commands
// could be "open", "syslog" and "close". Datalen is the length of Data buffer.
// the Data content is according with command. Data associated with command
// "open" shold be decoded with function DecodeOffer. Data associated with
// "syslog" is a syslog message and could be processed as string. Command
// "close" as no data associated.
type Message struct {
	Txnr int
	Command string
	Datalen int
	Data []byte
}

// This function must be called to validate options. Options could be nil, in
// this case default value are used and OPtion struct is returned. If Option
// are provided as argument, the Option returned is the same struct.
//
// Once the function ValidateOptions is called, the Options struct should not
// modified.
//
// The function prepare TLS connection opening all cryptographic elements (CA,
// certificate, private key, CRL). Validate wildcard format of ACLs, and set
// defaults for some not specified values.
func ValidateOptions(opts *Options)(*Options, error) {
	var ca_bytes []byte
	var data []byte
	var err error
	var bl *pem.Block
	var crt tls.Certificate
	var i int

	if opts == nil {
		opts = &Options{}
	}

	if opts.RecvSize == 0 {
		opts.RecvSize = 16384
	}

	if opts.Tls == Opt_tls_connection {

		// Load certificates
		if opts.Certificate == "" {
			return nil, fmt.Errorf("need certificate file")
		}
		if opts.PrivateKey == "" {
			return nil, fmt.Errorf("need private key file")
		}
		if opts.CACertificate == "" {
			return nil, fmt.Errorf("need ca file")
		}
		crt, err = tls.LoadX509KeyPair(opts.Certificate, opts.PrivateKey)
		if err != nil {
			return nil, err
		}
		opts.crt, _ = x509.ParseCertificate(crt.Certificate[0])

		// build TLS config
		opts.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{crt},
			VerifyPeerCertificate: opts.verifyPeerCertificate,
			ClientAuth: tls.RequireAndVerifyClientCert,
			RootCAs: x509.NewCertPool(),
			ClientCAs: x509.NewCertPool(),
		}

		// Load CA
		ca_bytes, err = os.ReadFile(opts.CACertificate)
		if err != nil {
			return nil, fmt.Errorf("can't read CA file %q: %s", opts.CACertificate, err.Error())
		}
		bl, _ = pem.Decode(ca_bytes)
		if bl == nil {
			return nil, fmt.Errorf("failed to parse CA file %q. Expect PEM format", opts.CACertificate)
		}
		if bl.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected kind of PEM block in file %q: expect \"CERTIFICATE\", got %q", opts.CACertificate, bl.Type)
		}
		opts.ca, err = x509.ParseCertificate(bl.Bytes)
		if err != nil {
			return nil, fmt.Errorf("can't parse CA file %q: %s", opts.CACertificate, err.Error())
		}
		opts.tlsConfig.RootCAs.AddCert(opts.ca)
		opts.tlsConfig.ClientCAs.AddCert(opts.ca)

		opts.vrfyOpts = x509.VerifyOptions{
			Roots: opts.tlsConfig.RootCAs,
			Intermediates: x509.NewCertPool(),
		}
		_, err = opts.crt.Verify(opts.vrfyOpts)
		if err != nil {
			return nil, fmt.Errorf("certificate %q not verified by ca %q: %s", opts.Certificate, opts.CACertificate, err.Error())
		}

		// Load CRL - Its useless loading CRL if there are no CA declared
		if opts.CACertificate != "" && opts.Crl != "" {
			data, err = os.ReadFile(opts.Crl)
			if err != nil {
				return nil, err
			}
			bl, _ = pem.Decode(data)
			if bl == nil {
				return nil, fmt.Errorf("failed to parse crl file %q. Expect PEM format", opts.Crl)
			}
			if bl.Type != "X509 CRL" {
				return nil, fmt.Errorf("unexpected kind of PEM block in file %q: expect \"X509 CRL\", got %q", opts.Crl, bl.Type)
			}
			opts.revocationList, err = x509.ParseRevocationList(bl.Bytes)
			if err != nil {
				return nil, fmt.Errorf("can't parse crl file %q: %s", opts.Crl, err.Error())
			}
			if !bytes.Equal(opts.ca.RawSubject, opts.revocationList.RawIssuer) {
				return nil, fmt.Errorf("crl file %q has unexpected issuer", opts.Crl)
			}
			err = opts.revocationList.CheckSignatureFrom(opts.ca)
			if err != nil {
				return nil, fmt.Errorf("can't use crl file %q: %s", opts.Crl, err.Error())
			}
		}

		// Validate acl
		for i, _ = range opts.CnAcl {
			_, err = filepath.Match(opts.CnAcl[i].Value, opts.CnAcl[i].Value)
			if err != nil {
				return nil, fmt.Errorf("acl pattern %q error: %s", opts.CnAcl[i].Value, err.Error())
			}
			if opts.CnAcl[i].Action != Acl_accept && opts.CnAcl[i].Action != Acl_reject {
				return nil, fmt.Errorf("acl action %d not exists. use %d or %d", opts.CnAcl[i].Action, Acl_accept, Acl_reject)
			}
		}
	}

	return opts, nil
}

func (opts *Options)verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate)(error) {
	var crt *x509.Certificate
	var revoked pkix.RevokedCertificate
	var err error
	var i int
	var match bool

	// At this point certificate validity and CA are validated.
	// Check CRL is needed and acceptance filter on cn.
	if len(rawCerts) == 0 {
		return fmt.Errorf("client certificate expected")
	}
	if len(rawCerts) > 1 {
		return fmt.Errorf("too many client certificate provided, expect 1, got %d", len(rawCerts))
	}
	crt, err = x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("client provides wrong certificate: %s", err.Error())
	}
	_, err = crt.Verify(opts.vrfyOpts)
	if err != nil {
		return fmt.Errorf("client provides certificate signed by unknown CA: %s", err.Error())
	}
	if opts.revocationList != nil {
		for _, revoked = range opts.revocationList.RevokedCertificates {
			if crt.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				return fmt.Errorf("client provides revoked certificate")
			}
		}
	}

	// check certificate name policy
	browse_acl: for i, _ = range opts.CnAcl {
		match, _ = filepath.Match(opts.CnAcl[i].Value, crt.Subject.CommonName)
		if match {
			switch opts.CnAcl[i].Action{
			case Acl_reject:
				return fmt.Errorf("client certificate cn %q forbidden by ACL", crt.Subject.CommonName)
			case Acl_accept:
				break browse_acl
			}
		}
	}

	return nil
}

// Handle new connection on the stream defined by "fd". The caller must ensure
// all the network processing as it want. (bind, listen, accept, goroutine, TLS,
// ...). "options" contains set of options to apply on this RELP session. The
// TLS options and common name ACL are not applicable in this mode. If the
// function retuns non nil "error" the connection could be close because. The
// function return RELP struct which is used to follow RELP stream.
func NewReadWriter(fd io.ReadWriter, options *Options)(*Relp, error) {
	var r *Relp

	r = &Relp{}
	r.opts = options

	// Configure file descriptors
	r.tcp_fd = nil
	r.tls_fd = nil
	r.fd = fd

	return r, nil
}

// Handle new connection on the TCP stream defined by "fd". The caller just
// ensure networks server part (bind, listen, accept). The RELP library process
// TLS protocol if activated. If the function retuns non nil "error" the
// connection could be close because. The function return RELP struct which is
// used to follow RELP stream.
func NewTcp(tcp_fd net.Conn, options *Options)(*Relp, error) {
	var r *Relp

	r = &Relp{}
	r.opts = options

	// Configure file descriptors
	r.tcp_fd = tcp_fd
	r.fd = tcp_fd

	// Enable native TLS
	if options.Tls == Opt_tls_connection {
		r.tls_fd = tls.Server(tcp_fd, r.opts.tlsConfig)
		r.fd = r.tls_fd
	}

	return r, nil
}

var err_proto error = fmt.Errorf("protocol error")

// this function read from min to max digits and return decoded value. The
// second returned value is the number of bytes eat, -1 if an error occurs.
func read_digit(min int, max int, buf []byte)(int, int) {
	var i int
	var gen64 uint64
	var err error

	for i = 0; i < len(buf); i++ {
		if buf[i] < '0' || buf[i] > '9' {
			break
		}
	}
	if i < min || i > max {
		return -1, -1
	}
	gen64, err = strconv.ParseUint(string(buf[:i]), 10, 32)
	if err != nil {
		return -1, -1
	}
	return int(gen64), i
}

// this function read from min to max alpha and return decoded value. The second
// returned value is the number of bytes eat, -1 if an error occurs
func read_alpha(min int, max int, buf []byte)(string, int) {
	var i int

	for i = 0; i < len(buf); i++ {
		if (buf[i] < 'a' || buf[i] > 'z') && (buf[i] < 'A' || buf[i] > 'Z') {
			break
		}
	}
	if i < min || i > max {
		return "", 0
	}
	return string(buf[:i]), i
}

// this function read all chars until encountering one of limit char or end. It
// returns the read string and the length consumed. Limit char are not consumed
func read_all_until(buf []byte, limits []byte)(string, int) {
	var i int
	var j int

	browse_buf: for i = 0; i < len(buf); i++ {
		for j = 0; j < len(limits); j++ {
			if buf[i] == limits[j] {
				break browse_buf
			}
		}
	}
	return string(buf[:i]), i
}

// Generic definitions:
// --------------------
//
// ALPHA = letter ; ('a'..'z', 'A'..'Z')
// NUMBER = 1*9DIGIT
// DIGIT = %d48-57
// LF = %d10
// SP = %d32
//
// RELP frame definition:
// ----------------------
//
// RELP-FRAME = HEADER DATA TRAILER
//
// HEADER = TXNR SP COMMAND SP DATALEN
// TXNR = NUMBER ; relp transaction number, monotonically increases, starts at 1
// #old:COMMAND = "open" / "syslog" / "close" / "rsp" / "abort" ; max length = 32
// COMMAND = 1*32ALPHA
// DATALEN = NUMBER
//
// DATA = [SP 1*OCTET] ; command-defined data, if DATALEN is 0, no data is present
// TRAILER = LF ; to detect framing errors and enhance human readibility
//
// So, header message is terminated by NUMBER SP or 0 LF.
//
// in success function returns message and length consumed,
// in error cases message is nil and code is:
//  -1: frame error
//  -2: need more data
const err_frame = -1
const err_need_more = -2
func decode_frame_header(data []byte)(*Message, int) {
	var i int
	var l int
	var txnr int
	var command string
	var datalen int

	// Expect number until encountering space
	if len(data) < 1 {
		return nil, err_need_more
	}
	i = 0
	txnr, l = read_digit(1, 9, data[0:])
	if l == -1 {
		return nil, err_frame
	}
	i += l
	if len(data) <= i {
		return nil, err_need_more
	}
	if data[i] != ' ' {
		return nil, err_frame
	}
	i++

	// Expect between 1 and 32 alpha chars until encoutering space
	if len(data) < 1 {
		return nil, err_need_more
	}
	command, l = read_alpha(1, 32, data[i:])
	if l == -1 {
		return nil, err_frame
	}
	i += l
	if len(data) <= i {
		return nil, err_need_more
	}
	if data[i] != ' ' {
		return nil, err_frame
	}
	i++

	// Expect datalen between 1 and 9 digit followed by space if
	// first digit != '0' or LF id first digit is '0'
	// Process first char with specific code. Second char is tested
	// for \n, otherwise a loop browse all digit until encountering
	// ' '
	if len(data) < 1 {
		return nil, err_need_more
	}
	datalen, l = read_digit(1, 9, data[i:])
	if l == -1 {
		return nil, err_frame
	}
	i += l
	if len(data) <= i {
		return nil, err_need_more
	}
	if datalen == 0 {
		if data[i] != '\n' {
			return nil, err_frame
		}
	} else {
		if data[i] != ' ' {
			return nil, err_frame
		}
		i++
	}

	return &Message{
		Txnr: txnr,
		Command: command,
		Datalen: datalen,
	}, i
}

// Low level receive function. It returns raw message which need parsing.
// Message "open" need to be parsed by DecodeOffer function. Message "syslog"
// just need string conversion. If the function returns error, the connection
// should be closed.
func (r *Relp)ReceiveMessage()(*Message, error) {
	var buffer []byte = make([]byte, r.opts.RecvSize)
	var n int
	var err error
	var msg *Message
	var code int

	// Start processing new frame. try first to process
	// bufferised data.
	for {
		msg, code = decode_frame_header(r.buffer)
		if msg != nil { // message decoded
			r.buffer = r.buffer[code:] // eat message header
			break
		}
		if code == err_frame { // protocol error
			return nil, err_proto
		}
		// err_need_more - need more data
		if r.closed {
			if len(r.buffer) == 0 {
				return nil, nil
			} else {
				return nil, err_proto
			}
		}
		n, err = r.fd.Read(buffer[:])
		if n > 0 {
			r.buffer = append(r.buffer, buffer[0:n]...)
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			r.closed = true
		}
	}

	for {
		if len(r.buffer) >= msg.Datalen {
			msg.Data = r.buffer[:msg.Datalen]
			r.buffer = r.buffer[msg.Datalen:]
			break
		}
		// need more data
		if r.closed {
			// if the client close connection at unexpected state
			// this is a protocol error
			return nil, err_proto
		}
		n, err = r.fd.Read(buffer[:])
		if n > 0 {
			r.buffer = append(r.buffer, buffer[0:n]...)
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			r.closed = true
		}
	}

	// Expect final \n
	for {
		if len(r.buffer) >= 1 {
			if r.buffer[0] != '\n' {
				return nil, err_proto
			}
			r.buffer = r.buffer[1:]
			return msg, nil
		}
		// need more data
		if r.closed {
			// if the client close connection at unexpected state
			// this is a protocol error
			return nil, err_proto
		}
		n, err = r.fd.Read(buffer[:])
		if n > 0 {
			r.buffer = append(r.buffer, buffer[0:n]...)
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			r.closed = true
		}
	}
}

// offer data definition:
// ----------------------
//
// OFFER = LF FEATURENAME ["=" VALUE *("," VALUE)]
// FEATURENAME = *32OCTET
// VALUE = *255OCTET
//
// Currently defined values:
//
// "relp_version" 1 args : NUMBER
//
// This offer describes the protocol version. It MUST be provided in the open command.
// It has one parameter, the numerical version id. The intial version is 1. There
// also exists an experimental version 0, which shall not be used in practice.
//
// "commands" Many args string
// This offer describes which commands are supported by the remote peer. Command that
// must be specified to drive the RELP protocol itself (e.g. "open", "close", "rsp")
// MUST NOT be specified. Optional commands must be specified. There may be multiple
// commands specified.
// Sample: commands=syslog,eventlog (eventlog is a hypothetical, not yet known command).
//
// Please note that new commands may be specified outside of the relp specification.
// Also note that if the server response does not include the command the client is
// interested in, this command MUST NOT be used. The client may then either resort
// to another, less featured supported command or may terminate the relp connection.
//
// "relp_software" Many args string
// This offer describes the software (library) that is processing the relp protocol.
// It is an optional offer. The idea is that when each peer knows which software on
// the other peer is handling the protocol, it may be able to work-around some known
// software issues. The "relp_software" has two parameters, the first one being the
// name of the software as it calls itself, the second one the version as it calls
// itself and the third one being an URL where information about this software may
// be found. It is suggested that all three parameters are given, but only the
// first one MUST actually be provided.
var version = "relp_version"
var command = "commands"
var softwar = "relp_software"

var cmd_sclose = "serverclose"
var cmd_strtls = "starttls"
var cmd_syslog = "syslog"

// This function decode "open" command. The message associated with "open"
// command is called "offer" which announce client supported options. If the
// function returns error the connection should be closed. In succes case, the
// fucntion returns map with offer options as string index. In version 0 and 1
// options are "relp_version", "commands" and "relp_software". "relp_version"
// contains client version. If the version sent is different from 0 or 1, the
// negociation should fail because the version is not supported by the library.
// "relp_software" is indicative and contains client version. "commands"
// contains the list of commands supported by client. Specification indicates
// "startls" and "syslog", in practice "startls" is never used because its not
// implemented in librelp. "syslog" is mandatory because its the only one format
// supported today.
func (r *Relp)DecodeOffer(msg *Message)(map[string][]interface{}, error) {
	var buf []byte
	var out map[string][]interface{} = make(map[string][]interface{})
	var l int
	var v int
	var s string

	buf = bytes.Clone(msg.Data)

	for {

		// decode feature name
		// according with doc, relp_version=1 introduces these features:
		// - relp_version
		// - commands
		// - relp_software
		if len(buf) >= len(version + "=") && string(buf[:len(version + "=")]) == version + "=" {
			// relp_version
			buf = buf[len(version + "="):]
			v, l = read_digit(1, 9, buf)
			if l == -1 {
				return nil, err_proto
			}
			buf = buf[l:]
			out[version] = []interface{}{v}

		} else if len(buf) >= len(command + "=") && string(buf[:len(command + "=")]) == command + "=" {
			// commands
			buf = buf[len(command + "="):]
			out[command] = nil
			for {
				if len(buf) >= len(cmd_sclose) && string(buf[:len(cmd_sclose)]) == cmd_sclose {
					out[command] = append(out[command], cmd_sclose)
					buf = buf[len(cmd_sclose):]
				} else if len(buf) >= len(cmd_strtls) && string(buf[:len(cmd_strtls)]) == cmd_strtls {
					out[command] = append(out[command], cmd_strtls)
					buf = buf[len(cmd_strtls):]
				} else if len(buf) >= len(cmd_syslog) && string(buf[:len(cmd_syslog)]) == cmd_syslog {
					out[command] = append(out[command], cmd_syslog)
					buf = buf[len(cmd_syslog):]
				} else {
					v = bytes.Index(buf, []byte{','})
					if v == -1 {
						return nil, fmt.Errorf("unknown announced command %q", string(buf))
					}
					return nil, fmt.Errorf("unknown announced command %q", string(buf[:v]))
				}
				if len(buf) == 0 || buf[0] != ',' {
					break
				}
				buf = buf[1:]
			}

		} else if len(buf) >= len(softwar + "=") && string(buf[:len(softwar + "=")]) == softwar + "=" {
			// relp_software
			buf = buf[len(softwar + "="):]
			out[softwar] = nil
			for {
				s, l = read_all_until(buf, []byte{',','\n'})
				out[softwar] = append(out[softwar], s)
				buf = buf[l:]
				if len(buf) == 0 || buf[0] != ',' {
					break
				}
				buf = buf[1:]
			}

		} else {
			v = bytes.Index(buf, []byte{'='})
			if v == -1 {
				return nil, err_proto
			}
			return nil, fmt.Errorf("unknown feature name %q", string(buf[:v]))
		}

		// Expect \n or end
		if len(buf) == 0 {
			return out, nil
		}
		if buf[0] != '\n' {
			return nil, err_proto
		}
		buf = buf[1:]
	}
}

// Just return log message, negociation is transparent for the caller. Note the
// message must be acknoledged using function AnswerOk or AnswerMulmtipleOk.
// This is the most valuable way to use RELP library, because the caller could
// send acknoledgements according with its processing. If the function return
// error, the connection should be closed.
func (r *Relp)ReceiveLog()(*Message, error) {
	var msg *Message
	var err error
	var out map[string][]interface{}
	var status bool
	var offer []string
	var message string

	// receive first message, wich must it "open"
	if !r.open {

		// wait for open message
		msg, err = r.ReceiveMessage()
		if err != nil {
			return nil, err
		}
		if msg == nil {
			return nil, io.EOF
		}
		if msg.Command != "open" {
			return nil, fmt.Errorf("expect \"open\" command, got %q", msg.Command)
		}

		// decode offer
		out, err = r.DecodeOffer(msg)
		if err != nil {
			return nil, err
		}

		// negicate offer
		status, offer, message = r.NegociateOffer(msg, out)

		// Answer offer
		if status {
			r.AnswerOffer(msg, message, offer)
		} else {
			r.AnswerError(msg, message)
			return nil, io.EOF
		}

		// Mark conneciton opened
		r.open = true
	}

	// receive next message
	msg, err = r.ReceiveMessage()
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, io.EOF
	}
	if msg.Command == "syslog" {
		return msg, nil
	}
	if msg.Command == "close" {
		r.AnswerOk(msg)
		return nil, io.EOF
	}

	return nil, fmt.Errorf("unexpected command %q", msg.Command)
}

// Just return log message as string, negociation and acknoledgement are
// transparent for the caller. If the function returns error, the connection
// should be closed. This function doesn't permit to control acknoledgements, so
/// use it with caution, logs could be loss during program processing.
func (r *Relp)ReceiveLogAndAck()(string, error) {
	var msg *Message
	var err error

	msg, err = r.ReceiveLog()
	if err != nil {
		return "", err
	}
	r.AnswerOk(msg)

	return string(msg.Data), nil
}

// Implements io.ReadCloser Read function. Negociation and acknoledgement are
// transparent for the caller. Log messages are separated by '\n', see the
// option StreamEscapeLf for more information. This function doesn't permit to
// control acknoledgements, so use it with caution, logs could be loss during
// program processing.
func (r *Relp)Read(p []byte)(int, error) {
	var msg *Message
	var err error
	var l int
	var p_len int
	var tmp_data []byte

	p_len = 0
	for {

		// fill buffer with current data
		if len(r.out_buffer) > 0 {
			l = len(r.out_buffer)
			if l > cap(p) - p_len {
				l = cap(p) - p_len
			}
			copy(p[p_len:p_len + l], r.out_buffer[:l])
			p_len += l
			r.out_buffer = r.out_buffer[l:]
		}

		// if buffer has no more capability, or
		// input buffer is empty and output
		// buffer contains some data, return it.
		if p_len >= cap(p) {
			return p_len, nil
		}
		if len(r.buffer) == 0 && p_len > 0 {
			return p_len, nil
		}

		// Read next message if buffer has space
		// and receive buffer contains data (we
		// suppose a message is full, or the end
		// will arrive asap
		msg, err = r.ReceiveLog()
		if err != nil {
			return 0, err
		}
		r.AnswerOk(msg)

		// copy data from message to read output buffer
		if r.opts.StreamEscapeLf {
			tmp_data = bytes.ReplaceAll(msg.Data, []byte{'\n'}, []byte{'\\', 'n'})
		} else {
			tmp_data = msg.Data
		}
		r.out_buffer = append(r.out_buffer, tmp_data...)
		r.out_buffer = append(r.out_buffer, '\n')
	}
}

// This function close the connection where the RELP library is responsible. If
// the caller gives a tcp.Conn, the library just close RELP and TLS connection.
// If the caller give an io.ReadWriter the library just close RELP. The caller
// is responsible closing connections it establish or accept.
func (r *Relp)Close()(error) {
	if r.tls_fd != nil {
		return r.tls_fd.Close()
	}
	return nil
}

// This function check protocol version and supported options. It must take
// "open" command message as input. The function returns negociation status,
// true to accept connection, false to reject with 500. the function return an
// array of strings which contains supported commands on server side according
// with commands announced by the client. Last string returned is a human
// readable short message for the RELP reponse. These value could be modified
// before sending response, but in most cases its useless. The result is send to
// the client throught the function AnswerOffer. If the negociation result is
// reject, the connexion should be closed.
func (r *Relp)NegociateOffer(msg *Message, offer map[string][]interface{})(bool, []string, string) {
	var ok bool
	var v []interface{}
	var i int
	var cmd string
	var out []string
	var announce_starttls bool
	var announce_syslog bool

	// Check version, we support version 0 and 1
	v, ok = offer[version]
	if !ok {
		return false, nil, "expect " + version
	}
	if len(v) != 1 {
		return false, nil, "wrong " + version + " value"
	}
	r.version, ok = v[0].(int)
	if !ok {
		return false, nil, "internal error"
	}
	if r.version > 1 {
		return false, nil, "unsupported version"
	}

	// Check known commands
	v, ok = offer[command]
	if ok {
		for i = 0; i < len(v); i++ {
			cmd, ok = v[i].(string)
			if !ok {
				return false, nil, "internal error"
			}
			switch cmd {
			case cmd_sclose:
				// strangely announced by client
				return false, nil, "unexpected command " + cmd_sclose
			case cmd_strtls:
				// support starttls
				announce_starttls = true
				if r.opts.Tls != Opt_tls_disabled &&
				   r.opts.Tls != Opt_tls_connection &&
				   r.opts.Tls != Opt_tls_offloading {
					out = append(out, command)
				}
			case cmd_syslog:
				// supported
				announce_syslog = true
				out = append(out, cmd_syslog)
			}
		}
	}

	if !announce_syslog {
		// useless connection
		return false, nil, "expect at least syslog command"
	}

	if !announce_starttls && r.opts.Tls == Opt_tls_required {
		// starttls required
		return false, nil, "starttls support required"
	}

	return true, out, "ok"
}

// RSP DATA CONTENT:
// RSP-HEADER = TXNR SP RSP-CODE [SP HUMANMSG] LF [CMDDATA]
// RSP-CODE = 200 / 500 ; 200 is ok, all the rest currently erros
// HUAMANMSG = *OCTET ; a human-readble message without LF in it
// CMDDATA = *OCTET ; semantics depend on original command
// TXNR is as in the relp frame, it is the TXNR of the frame being responded to.
//
// RSPDATA = STATUS SP HUMAN-TEXT [LF DATA]
// STATUS = 3DIGIT
// HUMAN-TEXT = *80ALPHA
// DATA = 1*OCTET
func (r *Relp)format(msg *Message, data []byte)([]byte) {
	var m []byte

	if len(data) == 0 {
		m = []byte(fmt.Sprintf("%d rsp 0\n", msg.Txnr))
	} else {
		m = []byte(fmt.Sprintf("%d rsp %d ", msg.Txnr, len(data)))
		m = append(m, data...)
		m = append(m, '\n')
	}

	return m
}

func (r *Relp)send(data []byte)(error) {
	var sent int
	var err error

	for {
		sent, err = r.fd.Write(data)
		if err != nil {
			return err
		}
		if sent == len(data) {
			return nil
		}
		data = data[sent:]
	}
}

// This function send answer to the client in response to "offer" command. The
// function require a msg to exploit Txnr, a short human readable message
// acknoledging "offer" command. Often this message is "Ok". And the list of
// commands proposed by the server. this list of command could be obtained by
// the function NegociateOffer which produce this list if communication  between
// client and server is possible. If the function return error, the connection
// should be closed.
func (r *Relp)AnswerOffer(msg *Message, message string, commands []string)(error) {
	var m string

	m = fmt.Sprintf("200 %s\nrelp_version=%d\nrelp_software=go-relp,v1.0\ncommands=%s",
	                message, r.version, strings.Join(commands, ","))
	return r.send(r.format(msg, []byte(m)))
}

// This function just answer ok message. It is used to acknolegde commands
// "syslog" and "close". If the function return error, the connection should be
// closed.
func (r *Relp)AnswerOk(msg *Message)(error) {
	return r.send(r.format(msg, []byte("200 Ok")))
}

// This function answer ok message for a lot of incoming messages. It is used to
// acknolegde a batch of commands "syslog". This function is designed to deal
// with batch of log messages. The server program can receive a lot of log
// message, store this lot of message with one write on disk, ans then
// acknoledge all the message to the client. If the function return error, the
// connection should be closed.
func (r *Relp)AnswerMulmtipleOk(msgs []*Message)(error) {
	var msg *Message
	var data []byte

	for _, msg = range msgs {
		data = append(data, r.format(msg, []byte("200 Ok"))...)
	}
	return r.send(data)
}

// This function just answer ko message. It is used to indicate an error while
// processing command. Commonly, sending an error is just below closing
// connexion, anyway, if the function return error, the connection should be
// closed.
func (r *Relp)AnswerError(msg *Message, message string)(error) {
	var m string

	m = fmt.Sprintf("500 %s", message)
	return r.send(r.format(msg, []byte(m)))
}
