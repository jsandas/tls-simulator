package ftls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Protocol specific errors.
var (
	ErrStartTLSNotSupported = errors.New("STARTTLS not supported by server")
	ErrInvalidResponse      = errors.New("invalid server response")
	ErrUnsupportedProtocol  = errors.New("unsupported protocol")
)

// StartTLSProtocol defines the interface for protocol-specific STARTTLS implementations.
type StartTLSProtocol interface {
	// Handshake performs the protocol-specific STARTTLS negotiation
	Handshake(ctx context.Context, rw *bufio.ReadWriter) error
	// Name returns the protocol name
	Name() string
}

// baseProtocol implements common functionality for all STARTTLS protocols.
type baseProtocol struct {
	name     string
	greetMsg *regexp.Regexp
	authMsg  string
	respMsg  *regexp.Regexp
}

func newBaseProtocol(name, greetPattern, auth, respPattern string) baseProtocol {
	return baseProtocol{
		name:     name,
		greetMsg: regexp.MustCompile(greetPattern),
		authMsg:  auth,
		respMsg:  regexp.MustCompile(respPattern),
	}
}

// SMTP protocol implementation.
type smtpProtocol struct {
	baseProtocol
}

func newSMTPProtocol() *smtpProtocol {
	return &smtpProtocol{
		baseProtocol: newBaseProtocol("smtp", "^220 ", "STARTTLS\r\n", "^220 "),
	}
}

func (p *smtpProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("smtp: greeting failed: %w", err)
	}

	if err := p.sendEHLO(ctx, rw); err != nil {
		return fmt.Errorf("smtp: EHLO failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("smtp: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *smtpProtocol) Name() string {
	return p.name
}

func (p *smtpProtocol) sendEHLO(ctx context.Context, rw *bufio.ReadWriter) error {
	if _, err := rw.WriteString("EHLO tlstools.com\r\n"); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}

	for {
		line, err := readLine(ctx, rw.Reader)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(line, "250") {
			return fmt.Errorf("%w: unexpected EHLO response: %s", ErrInvalidResponse, line)
		}

		if rw.Reader.Buffered() == 0 {
			break
		}
	}

	return nil
}

// IMAP protocol implementation.
type imapProtocol struct {
	baseProtocol
}

func newIMAPProtocol() *imapProtocol {
	return &imapProtocol{
		baseProtocol: newBaseProtocol("imap", "^\\* ", "a001 STARTTLS\r\n", "^a001 OK "),
	}
}

func (p *imapProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("imap: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("imap: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *imapProtocol) Name() string {
	return p.name
}

// POP3 protocol implementation.
type pop3Protocol struct {
	baseProtocol
}

func newPOP3Protocol() *pop3Protocol {
	return &pop3Protocol{
		baseProtocol: newBaseProtocol("pop3", "^\\+OK ", "STLS\r\n", "^\\+OK "),
	}
}

func (p *pop3Protocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("pop3: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("pop3: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *pop3Protocol) Name() string {
	return p.name
}

// FTP protocol implementation.
type ftpProtocol struct {
	baseProtocol
}

func newFTPProtocol() *ftpProtocol {
	return &ftpProtocol{
		baseProtocol: newBaseProtocol("ftp", "^220 ", "AUTH TLS\r\n", "^234 "),
	}
}

func (p *ftpProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("ftp: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("ftp: AUTH TLS failed: %w", err)
	}

	return nil
}

func (p *ftpProtocol) Name() string {
	return p.name
}

// Helper functions.
func expectGreeting(ctx context.Context, rw *bufio.ReadWriter, pattern *regexp.Regexp) error {
	for {
		line, err := readLine(ctx, rw.Reader)
		if err != nil {
			return err
		}

		if pattern.MatchString(line) {
			return nil
		}
	}
}

func sendStartTLS(ctx context.Context, rw *bufio.ReadWriter, authMsg string, respPattern *regexp.Regexp) error {
	if _, err := rw.WriteString(authMsg); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}

	line, err := readLine(ctx, rw.Reader)
	if err != nil {
		return err
	}

	if !respPattern.MatchString(line) {
		return fmt.Errorf("%w: %s", ErrStartTLSNotSupported, strings.TrimSpace(line))
	}

	return nil
}

func readLine(ctx context.Context, r *bufio.Reader) (string, error) {
	// Create a channel for the read operation
	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		line, err := r.ReadString('\n')
		if err != nil {
			errCh <- err
			return
		}
		lineCh <- line
	}()

	// Wait for either the context to be done or the read to complete
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-errCh:
		return "", err
	case line := <-lineCh:
		return line, nil
	}
}

// Protocol registry.
var protocols = map[string]func() StartTLSProtocol{
	"21":  func() StartTLSProtocol { return newFTPProtocol() },
	"25":  func() StartTLSProtocol { return newSMTPProtocol() },
	"587": func() StartTLSProtocol { return newSMTPProtocol() },
	"110": func() StartTLSProtocol { return newPOP3Protocol() },
	"143": func() StartTLSProtocol { return newIMAPProtocol() },
}

// StartTLS initiates a STARTTLS handshake for supported protocols.
func StartTLS(ctx context.Context, conn net.Conn, port string) error {
	// Check if this is a STARTTLS protocol
	protocolFactory, ok := protocols[port]
	if !ok {
		// These ports use direct TLS connections
		switch port {
		case "443", "465", "993", "995", "3389":
			return nil
		default:
			return fmt.Errorf("%w: port %s", ErrUnsupportedProtocol, port)
		}
	}

	protocol := protocolFactory()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	return protocol.Handshake(ctx, rw)
}
