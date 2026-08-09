package simulator

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
)

// netErrorMock implements net.Error interface for testing isTimeoutError.
type netErrorMock struct {
	timeout bool
}

func (e *netErrorMock) Error() string   { return "mock net error" }
func (e *netErrorMock) Timeout() bool   { return e.timeout }
func (e *netErrorMock) Temporary() bool { return false }

func TestPerformTLSHandshake(t *testing.T) {
	t.Run("invalid server address format", func(t *testing.T) {
		_, err := PerformTLSHandshake(tls.VersionTLS12, nil, nil, "invalid-address-no-port")
		if err == nil {
			t.Fatal("expected error for invalid server address, got nil")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		// Listen and immediately close to get a free port that is guaranteed not accepting connections
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}

		addr := l.Addr().String()
		_ = l.Close()

		_, err = PerformTLSHandshake(tls.VersionTLS12, nil, nil, addr)
		if err == nil {
			t.Fatal("expected error for refused connection, got nil")
		}
	})

	t.Run("valid TLS 1.2 handshake", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)

			sh := &ftls.ServerHelloMsg{
				Vers:        ftls.VersionTLS12,
				Random:      make([]byte, 32),
				CipherSuite: 0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			}

			shBytes, err := sh.Marshal()
			if err != nil {
				return
			}

			record, err := createTLSRecord(shBytes)
			if err != nil {
				return
			}

			_, _ = conn.Write(record)

			time.Sleep(3 * time.Second)
		}()

		res, err := PerformTLSHandshake(tls.VersionTLS12, nil, nil, l.Addr().String())
		if err != nil {
			t.Fatalf("PerformTLSHandshake failed: %v", err)
		}

		if res.Protocol != tls.VersionTLS12 {
			t.Errorf("expected protocol %d, got %d", tls.VersionTLS12, res.Protocol)
		}

		if res.Cipher != 0xc02f {
			t.Errorf("expected cipher 0xc02f, got 0x%x", res.Cipher)
		}
	})

	t.Run("valid TLS 1.3 handshake", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)

			sh := &ftls.ServerHelloMsg{
				Vers:             ftls.VersionTLS12, // Legacy version in header for TLS 1.3
				SupportedVersion: ftls.VersionTLS13,
				Random:           make([]byte, 32),
				CipherSuite:      0x1301, // TLS_AES_128_GCM_SHA256
				ServerShare: ftls.KeyShare{
					Group: ftls.X25519,
					Data:  make([]byte, 32),
				},
			}

			shBytes, err := sh.Marshal()
			if err != nil {
				return
			}

			record, err := createTLSRecord(shBytes)
			if err != nil {
				return
			}

			_, _ = conn.Write(record)

			time.Sleep(3 * time.Second)
		}()

		res, err := PerformTLSHandshake(tls.VersionTLS13, nil, nil, l.Addr().String())
		if err != nil {
			t.Fatalf("PerformTLSHandshake failed: %v", err)
		}

		if res.Protocol != tls.VersionTLS13 {
			t.Errorf("expected protocol %d, got %d", tls.VersionTLS13, res.Protocol)
		}

		if res.Cipher != 0x1301 {
			t.Errorf("expected cipher 0x1301, got 0x%x", res.Cipher)
		}

		if res.CurveID != ftls.X25519 {
			t.Errorf("expected curve ID X25519, got %d", res.CurveID)
		}
	})

	t.Run("handshake with server key exchange", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		go func() {
			var combinedPayload []byte

			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)

			sh := &ftls.ServerHelloMsg{
				Vers:        ftls.VersionTLS12,
				Random:      make([]byte, 32),
				CipherSuite: 0xc02f,
			}

			shBytes, err := sh.Marshal()
			if err != nil {
				return
			}

			combinedPayload = append(combinedPayload, shBytes...)

			ske := &ftls.ServerKeyExchangeMsg{
				Key: []byte{
					0x03,       // named curve
					0x00, 0x1d, // X25519 curve ID
					0x20, // 32 bytes key length
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
					17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
				},
			}

			skeBytes, err := ske.Marshal()
			if err != nil {
				return
			}

			// Combine ServerHello and ServerKeyExchange into a single record payload
			combinedPayload = append(combinedPayload, skeBytes...)

			record, err := createTLSRecord(combinedPayload)
			if err != nil {
				return
			}

			_, _ = conn.Write(record)

			time.Sleep(3 * time.Second)
		}()

		res, err := PerformTLSHandshake(tls.VersionTLS12, nil, nil, l.Addr().String())
		if err != nil {
			t.Fatalf("PerformTLSHandshake failed: %v", err)
		}

		if res.CurveID != ftls.X25519 {
			t.Errorf("expected curve ID %v, got %v", ftls.X25519, res.CurveID)
		}
	})

	t.Run("server sends invalid response", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("not a valid tls response"))

			time.Sleep(3 * time.Second)
		}()

		_, err = PerformTLSHandshake(tls.VersionTLS12, nil, nil, l.Addr().String())
		if err == nil {
			t.Fatal("expected error for invalid server response, got nil")
		}
	})

	t.Run("server sends no data timeout", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer l.Close()

		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)

			time.Sleep(3 * time.Second)
		}()

		_, err = PerformTLSHandshake(tls.VersionTLS12, nil, nil, l.Addr().String())
		if err == nil {
			t.Fatal("expected error for server timeout with no data, got nil")
		}
	})
}

func TestBuildClientHello(t *testing.T) {
	t.Run("TLS 1.2 defaults", func(t *testing.T) {
		ch := buildClientHello(tls.VersionTLS12, nil, nil, "example.com")

		if ch.Vers != tls.VersionTLS12 {
			t.Errorf("expected version %d, got %d", tls.VersionTLS12, ch.Vers)
		}

		if ch.ServerName != "example.com" {
			t.Errorf("expected SNI example.com, got %s", ch.ServerName)
		}

		if len(ch.CipherSuites) != len(ftls.DefaultCipherSuites) {
			t.Errorf("expected default cipher suites length %d, got %d", len(ftls.DefaultCipherSuites), len(ch.CipherSuites))
		}

		if len(ch.SupportedCurves) != len(ftls.DefaultCurves) {
			t.Errorf("expected default curves length %d, got %d", len(ftls.DefaultCurves), len(ch.SupportedCurves))
		}
	})

	t.Run("TLS 1.3 defaults", func(t *testing.T) {
		ch := buildClientHello(tls.VersionTLS13, nil, nil, "example.com")

		if len(ch.SupportedVersions) != 1 || ch.SupportedVersions[0] != tls.VersionTLS13 {
			t.Errorf("expected supported versions [1304], got %v", ch.SupportedVersions)
		}

		if len(ch.CipherSuites) != len(ftls.DefaultCipherSuitesTLS13) {
			t.Errorf("expected TLS 1.3 default ciphers length %d, got %d",
				len(ftls.DefaultCipherSuitesTLS13), len(ch.CipherSuites))
		}
	})

	t.Run("custom ciphers and curves", func(t *testing.T) {
		ciphers := []uint16{0xc02f, 0xc030}
		curves := []ftls.CurveID{ftls.X25519}
		ch := buildClientHello(tls.VersionTLS12, ciphers, curves, "custom.test")

		if len(ch.CipherSuites) != 2 || ch.CipherSuites[0] != 0xc02f {
			t.Errorf("unexpected cipher suites: %v", ch.CipherSuites)
		}

		if len(ch.SupportedCurves) != 1 || ch.SupportedCurves[0] != ftls.X25519 {
			t.Errorf("unexpected curves: %v", ch.SupportedCurves)
		}
	})
}

func TestCreateTLSRecord(t *testing.T) {
	t.Run("valid message", func(t *testing.T) {
		msg := []byte{0x01, 0x02, 0x03, 0x04}

		record, err := createTLSRecord(msg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedLen := 5 + len(msg)
		if len(record) != expectedLen {
			t.Fatalf("expected record length %d, got %d", expectedLen, len(record))
		}

		if record[0] != 0x16 || record[1] != 0x03 || record[2] != 0x03 {
			t.Errorf("unexpected TLS record header: %v", record[:3])
		}

		if int(record[3])<<8|int(record[4]) != len(msg) {
			t.Errorf("unexpected length bytes in record: %v", record[3:5])
		}
	})

	t.Run("message too large", func(t *testing.T) {
		largeMsg := make([]byte, 65536)

		_, err := createTLSRecord(largeMsg)
		if err == nil {
			t.Fatal("expected error for oversized message, got nil")
		}
	})
}

func TestParseServerResponse(t *testing.T) {
	t.Run("nil ServerHello", func(t *testing.T) {
		_, err := parseServerResponse(nil, nil)
		if err == nil {
			t.Fatal("expected error for nil serverHelloBytes, got nil")
		}
	})

	t.Run("unmarshal ServerHello failure", func(t *testing.T) {
		_, err := parseServerResponse([]byte{0x00, 0x01}, nil)
		if err == nil {
			t.Fatal("expected unmarshal failure error, got nil")
		}
	})

	t.Run("valid ServerHello without key exchange", func(t *testing.T) {
		sh := &ftls.ServerHelloMsg{
			Vers:        ftls.VersionTLS12,
			Random:      make([]byte, 32),
			CipherSuite: 0xc02f,
		}

		shBytes, err := sh.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal ServerHello: %v", err)
		}

		res, err := parseServerResponse(shBytes, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if res.Protocol != tls.VersionTLS12 {
			t.Errorf("expected protocol %d, got %d", tls.VersionTLS12, res.Protocol)
		}

		if res.Cipher != 0xc02f {
			t.Errorf("expected cipher 0xc02f, got 0x%x", res.Cipher)
		}
	})

	t.Run("unmarshal ServerKeyExchange failure", func(t *testing.T) {
		sh := &ftls.ServerHelloMsg{
			Vers:        ftls.VersionTLS12,
			Random:      make([]byte, 32),
			CipherSuite: 0xc02f,
		}

		shBytes, err := sh.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal ServerHello: %v", err)
		}

		invalidSkeBytes := []byte{0x0c, 0x00}

		_, err = parseServerResponse(shBytes, invalidSkeBytes)
		if err == nil {
			t.Fatal("expected error for invalid ServerKeyExchange, got nil")
		}
	})

	t.Run("ServerKeyExchange GetKey error", func(t *testing.T) {
		sh := &ftls.ServerHelloMsg{
			Vers:        ftls.VersionTLS12,
			Random:      make([]byte, 32),
			CipherSuite: 0xc02f,
		}

		shBytes, err := sh.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal ServerHello: %v", err)
		}

		ske := &ftls.ServerKeyExchangeMsg{
			Key: []byte{0x03, 0x00}, // malformed key
		}

		skeBytes, err := ske.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal ServerKeyExchange: %v", err)
		}

		res, err := parseServerResponse(shBytes, skeBytes)
		if err != nil {
			t.Fatalf("unexpected outer error: %v", err)
		}

		if res.Error == nil {
			t.Fatal("expected res.Error to be set for malformed key exchange")
		}
	})
}

func TestGetHandshakeMessages(t *testing.T) {
	t.Run("no handshake messages found", func(t *testing.T) {
		// Non-handshake record type (0x15 = Alert)
		data := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}

		_, _, err := getHandshakeMessages(data)
		if err == nil {
			t.Fatal("expected error when no handshake message is present, got nil")
		}
	})

	t.Run("valid ServerHello message extracted", func(t *testing.T) {
		sh := &ftls.ServerHelloMsg{
			Vers:        ftls.VersionTLS12,
			Random:      make([]byte, 32),
			CipherSuite: 0xc02f,
		}

		shBytes, err := sh.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal ServerHello: %v", err)
		}

		record, err := createTLSRecord(shBytes)
		if err != nil {
			t.Fatalf("failed to create record: %v", err)
		}

		shExtracted, skeExtracted, err := getHandshakeMessages(record)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if shExtracted == nil {
			t.Fatal("expected non-nil ServerHello")
		}

		if skeExtracted != nil {
			t.Errorf("expected nil ServerKeyExchange, got %v", skeExtracted)
		}
	})

	t.Run("truncated record data", func(t *testing.T) {
		// Header says length 10, but payload is only 2 bytes
		data := []byte{0x16, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x02}

		_, _, err := getHandshakeMessages(data)
		if err == nil {
			t.Fatal("expected error for truncated record data, got nil")
		}
	})
}

func TestIsTimeoutError(t *testing.T) {
	t.Run("net error with timeout true", func(t *testing.T) {
		err := &netErrorMock{timeout: true}
		if !isTimeoutError(err) {
			t.Error("expected isTimeoutError to return true")
		}
	})

	t.Run("net error with timeout false", func(t *testing.T) {
		err := &netErrorMock{timeout: false}
		if isTimeoutError(err) {
			t.Error("expected isTimeoutError to return false")
		}
	})

	t.Run("standard non-net error", func(t *testing.T) {
		err := errors.New("generic error")
		if isTimeoutError(err) {
			t.Error("expected isTimeoutError to return false for generic error")
		}
	})
}
