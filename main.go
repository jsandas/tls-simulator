package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jsandas/starttls-go/starttls"
	"github.com/jsandas/tls-simulator/ftls"
)

// TLSHandshakeResult contains the parsed ServerHello and key exchange information.
type TLSHandshakeResult struct {
	ServerHello *ftls.ServerHelloMsg
	Protocol    int
	Cipher      uint16
	// KeyType     string
	// KeySize     int
	CurveID ftls.CurveID
	Error   error
}

// buildClientHello creates a ClientHelloMsg with the specified parameters.
func buildClientHello(protocolVer uint16, ciphers []uint16, curves []ftls.CurveID, sniHost string) *ftls.ClientHelloMsg {
	clientMsg := &ftls.ClientHelloMsg{
		Vers:               protocolVer,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{ftls.CompressionNone},
		ServerName:         sniHost,
		SessionId:          []byte{},
		Random: []byte{0x3a, 0x6e, 0x72, 0xcc, 0xf9, 0x3b, 0x29, 0xbb, 0xfb, 0x2d, 0xd0, 0xa3,
			0x2b, 0x76, 0x3a, 0x9d, 0x28, 0x89, 0x11, 0xae, 0xfe, 0x4f, 0xf, 0x37, 0x6d,
			0xce, 0xa0, 0x4a, 0xf, 0x8d, 0x6e, 0x15},
		SupportedPoints: []uint8{ftls.PointFormatUncompressed},
		SupportedCurves: curves,
		SupportedSignatureAlgorithms: []ftls.SignatureScheme{
			ftls.PSSWithSHA512, ftls.PKCS1WithSHA512, ftls.ECDSAWithP521AndSHA512,
			ftls.PSSWithSHA384, ftls.PKCS1WithSHA384, ftls.ECDSAWithP384AndSHA384,
			ftls.PKCS1WithSHA256, ftls.PSSWithSHA256, ftls.ECDSAWithP256AndSHA256,
			ftls.PKCS1WithSHA1, ftls.ECDSAWithSHA1,
		},
		KeyShares: []ftls.KeyShare{{
			Group: ftls.X25519,
			Data: []byte{0xed, 0x7, 0xea, 0x17, 0xf2, 0x33, 0x83, 0x69, 0x5, 0x94, 0x89,
				0xc7, 0x9f, 0x57, 0x19, 0xcd, 0x6b, 0xcb, 0xe7, 0x22, 0x3d, 0xb1, 0x1b,
				0x8b, 0xe1, 0x52, 0x1d, 0xc2, 0x49, 0x48, 0xe4, 0x3d},
		}},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}

	if protocolVer == tls.VersionTLS13 {
		clientMsg.SupportedVersions = []uint16{tls.VersionTLS13}
		if len(ciphers) == 0 {
			clientMsg.CipherSuites = ftls.DefaultCipherSuitesTLS13
		}
	} else if len(ciphers) == 0 {
		clientMsg.CipherSuites = ftls.DefaultCipherSuites
	}

	if len(curves) == 0 {
		clientMsg.SupportedCurves = ftls.DefaultCurves
	}

	return clientMsg
}

// createTLSRecord wraps a handshake message in a TLS record.
func createTLSRecord(handshakeMsg []byte) ([]byte, error) {
	messageLen := len(handshakeMsg)
	if messageLen > 65535 {
		return nil, fmt.Errorf("handshake message too large: %d bytes", messageLen)
	}

	record := make([]byte, 5+messageLen)
	record[0] = 0x16                                            // Handshake record type
	record[1] = 0x03                                            // TLS version major
	record[2] = 0x03                                            // TLS version minor
	binary.BigEndian.PutUint16(record[3:5], uint16(messageLen)) // Record length
	copy(record[5:], handshakeMsg)                              // Handshake data

	return record, nil
}

// parseServerResponse processes the server's response and creates a TLSHandshakeResult.
func parseServerResponse(serverHelloBytes, serverKeyExchangeBytes []byte) (*TLSHandshakeResult, error) {
	result := &TLSHandshakeResult{}

	if serverHelloBytes == nil {
		return nil, fmt.Errorf("no ServerHello message received")
	}

	serverHello := &ftls.ServerHelloMsg{}
	if !serverHello.Unmarshal(serverHelloBytes) {
		return nil, fmt.Errorf("failed to unmarshal ServerHello")
	}

	result.ServerHello = serverHello
	if serverHello.SupportedVersion != 0 {
		result.Protocol = int(serverHello.SupportedVersion)
	} else {
		result.Protocol = int(serverHello.Vers)
	}

	result.Cipher = serverHello.CipherSuite

	if serverHello.ServerShare.Group != 0 {
		result.CurveID = serverHello.ServerShare.Group
	}

	if serverKeyExchangeBytes != nil {
		serverKeyExchange := &ftls.ServerKeyExchangeMsg{}
		if !serverKeyExchange.Unmarshal(serverKeyExchangeBytes) {
			return nil, fmt.Errorf("failed to unmarshal ServerKeyExchange")
		}

		if err := serverKeyExchange.GetKey(); err != nil {
			result.Error = fmt.Errorf("failed to parse ServerKeyExchange: %v", err)
		} else {
			result.ServerHello.ServerShare.Group = serverKeyExchange.CurveID
			result.CurveID = serverKeyExchange.CurveID
		}
	}

	return result, nil
}

// PerformTLSHandshake performs a TLS handshake with the specified parameters.
func PerformTLSHandshake(protocolVer uint16, ciphers []uint16, curves []ftls.CurveID, serverAddr string) (*TLSHandshakeResult, error) {
	sniHost, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %v", err)
	}

	clientMsg := buildClientHello(protocolVer, ciphers, curves, sniHost)

	clientHello, err := clientMsg.MarshalMsg(false)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ClientHello: %v", err)
	}

	tlsRecord, err := createTLSRecord(clientHello)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS record: %v", err)
	}

	resp, err := sendClientHello(serverAddr, tlsRecord)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %v", err)
	}

	serverHello, serverKeyExchange, err := getHandshakeMessages(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get handshake messages: %v", err)
	}

	return parseServerResponse(serverHello, serverKeyExchange)
}

func sendClientHello(addr string, clientHello []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	// Get the port for STARTTLS check
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	// Attempt STARTTLS if needed for this port
	ctx := context.Background()
	if err := starttls.StartTLS(ctx, conn, port); err != nil && !errors.Is(err, starttls.ErrUnsupportedProtocol) {
		return nil, fmt.Errorf("STARTTLS negotiation failed: %v", err)
	}

	// Set write deadline and send ClientHello
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %v", err)
	}
	if _, err := conn.Write(clientHello); err != nil {
		return nil, fmt.Errorf("failed to write ClientHello: %v", err)
	}

	// Set read deadline and read response
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}

	var resp []byte

	buffer := make([]byte, 4096)

	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			resp = append(resp, buffer[:n]...)
		}
		if err != nil {
			// If we got some data before the error, and it's a timeout,
			// we consider this a success - the server might have just closed
			// the connection after sending the response
			if len(resp) > 0 && isTimeoutError(err) {
				return resp, nil
			}
			if isTimeoutError(err) {
				return nil, fmt.Errorf("read timeout: %v", err)
			}

			return nil, fmt.Errorf("read error: %v", err)
		}
	}
}

// isTimeoutError returns true if the error is a timeout.
func isTimeoutError(err error) bool {
	if err, ok := err.(net.Error); ok {
		return err.Timeout()
	}

	return false
}

func getHandshakeMessages(data []byte) (serverHello, serverKeyExchange []byte, err error) {
	i := 0
	for i+5 <= len(data) {
		// Parse TLS record header
		contentType := data[i]

		length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if i+5+length > len(data) {
			break // Malformed record
		}

		recordPayload := data[i+5 : i+5+length]

		if contentType == 0x16 { // Handshake
			// Parse handshake messages within this record
			j := 0
			for j+4 <= len(recordPayload) {
				handshakeType := recordPayload[j]
				// Calculate handshake length using uint32 for safe arithmetic
				handshakeLenUint := uint32(recordPayload[j+1])<<16 | uint32(recordPayload[j+2])<<8 | uint32(recordPayload[j+3])

				// Check if the calculated length exceeds the maximum safe int value
				if handshakeLenUint > (1<<31 - 1) {
					break // Length too large, skip this message
				}

				handshakeLen := int(handshakeLenUint)
				if handshakeLen < 0 || j+4+handshakeLen > len(recordPayload) {
					break // Malformed handshake message
				}

				handshakeMessage := recordPayload[j : j+4+handshakeLen]

				switch handshakeType {
				case ftls.TypeServerHello:
					if serverHello == nil {
						serverHello = handshakeMessage
					}
				case ftls.TypeServerKeyExchange:
					if serverKeyExchange == nil {
						serverKeyExchange = handshakeMessage
					}
				}

				j += 4 + handshakeLen
			}
		}

		i += 5 + length
	}

	if serverHello == nil && serverKeyExchange == nil {
		return nil, nil, fmt.Errorf("no ServerHello or ServerKeyExchange found in response")
	}

	return serverHello, serverKeyExchange, nil
}
