package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
)

// TLSHandshakeResult contains the parsed ServerHello and key exchange information
type TLSHandshakeResult struct {
	ServerHello *ftls.ServerHelloMsg
	Protocol    int
	Cipher      uint16
	// KeyType     string
	// KeySize     int
	CurveID ftls.CurveID
	Error   error
}

// PerformTLSHandshake performs a TLS handshake with the specified parameters
// protocolVer: TLS protocol version (e.g., tls.VersionTLS12)
// ciphers: list of cipher suites to offer
// curves: list of elliptic curves to offer
// serverAddr: server address (e.g., "localhost:443")
func PerformTLSHandshake(protocolVer uint16, ciphers []uint16, curves []ftls.CurveID, serverAddr string) (*TLSHandshakeResult, error) {
	// parse serverAddr to extract SNI host
	// For simplicity, we assume serverAddr is in the format "host:port"
	sniHost, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %v", err)
	}

	// Build ClientHello message
	clientMsg := ftls.ClientHelloMsg{
		Vers:               protocolVer,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{ftls.CompressionNone},
		ServerName:         sniHost,
		SessionId:          []byte{},
		Random: []byte{0x3a, 0x6e, 0x72, 0xcc, 0xf9, 0x3b, 0x29, 0xbb, 0xfb, 0x2d, 0xd0, 0xa3,
			0x2b, 0x76, 0x3a, 0x9d, 0x28, 0x89, 0x11, 0xae, 0xfe, 0x4f, 0xf, 0x37, 0x6d,
			0xce, 0xa0, 0x4a, 0xf, 0x8d, 0x6e, 0x15},
		// SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10},
		SupportedPoints: []uint8{ftls.PointFormatUncompressed},
		SupportedCurves: curves,
		SupportedSignatureAlgorithms: []ftls.SignatureScheme{
			ftls.PSSWithSHA512,
			ftls.PKCS1WithSHA512,
			ftls.ECDSAWithP521AndSHA512,
			ftls.PSSWithSHA384,
			ftls.PKCS1WithSHA384,
			ftls.ECDSAWithP384AndSHA384,
			ftls.PKCS1WithSHA256,
			ftls.PSSWithSHA256,
			ftls.ECDSAWithP256AndSHA256,
			ftls.PKCS1WithSHA1,
			ftls.ECDSAWithSHA1,
		},
		KeyShares: []ftls.KeyShare{
			{
				Group: ftls.X25519,
				Data:  []byte{0xed, 0x7, 0xea, 0x17, 0xf2, 0x33, 0x83, 0x69, 0x5, 0x94, 0x89, 0xc7, 0x9f, 0x57, 0x19, 0xcd, 0x6b, 0xcb, 0xe7, 0x22, 0x3d, 0xb1, 0x1b, 0x8b, 0xe1, 0x52, 0x1d, 0xc2, 0x49, 0x48, 0xe4, 0x3d},
			},
		},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}

	if protocolVer == tls.VersionTLS13 {
		clientMsg.SupportedVersions = []uint16{tls.VersionTLS13}
	}

	if len(ciphers) == 0 || ciphers == nil {
		if protocolVer == tls.VersionTLS13 {
			clientMsg.CipherSuites = ftls.DefaultCipherSuitesTLS13
		} else {
			clientMsg.CipherSuites = ftls.DefaultCipherSuites
		}
	}

	if len(curves) == 0 || curves == nil {
		clientMsg.SupportedCurves = defaultCurves
	}

	clientHello, err := clientMsg.MarshalMsg(false)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ClientHello: %v", err)
	}

	// Wrap the handshake message in a TLS record
	tlsRecord := make([]byte, 5+len(clientHello))
	tlsRecord[0] = 0x16                                                  // Handshake record type
	tlsRecord[1] = 0x03                                                  // TLS version major
	tlsRecord[2] = 0x03                                                  // TLS version minor
	binary.BigEndian.PutUint16(tlsRecord[3:5], uint16(len(clientHello))) // Record length
	copy(tlsRecord[5:], clientHello)                                     // Handshake data

	// Send ClientHello and receive response
	resp, err := sendClientHello(serverAddr, tlsRecord)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %v", err)
	}

	// Parse handshake messages
	serverHelloBytes, serverKeyExchangeBytes, err := getHandshakeMessages(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get handshake messages: %v", err)
	}

	result := &TLSHandshakeResult{}

	// Parse ServerHello
	if serverHelloBytes != nil {
		serverHello := &ftls.ServerHelloMsg{}
		success := serverHello.Unmarshal(serverHelloBytes)
		if !success {
			return nil, fmt.Errorf("failed to unmarshal ServerHello")
		}
		result.ServerHello = serverHello
		if serverHello.SupportedVersion != 0 {
			result.Protocol = int(serverHello.SupportedVersion)
		} else {
			result.Protocol = int(serverHello.Vers)
		}
		result.Cipher = serverHello.CipherSuite
	}

	if result.ServerHello.ServerShare.Group != 0 {
		result.CurveID = result.ServerHello.ServerShare.Group
	}

	// Parse ServerKeyExchange if available
	if serverKeyExchangeBytes != nil {
		serverKeyExchange := &ftls.ServerKeyExchangeMsg{}
		success := serverKeyExchange.Unmarshal(serverKeyExchangeBytes)
		if !success {
			return nil, fmt.Errorf("failed to unmarshal ServerKeyExchange")
		}

		// Get the key exchange information using the built-in method
		err := serverKeyExchange.GetKey()
		if err != nil {
			result.Error = fmt.Errorf("failed to parse ServerKeyExchange: %v", err)
		} else {
			result.ServerHello.ServerShare.Group = serverKeyExchange.CurveID
			result.CurveID = serverKeyExchange.CurveID
		}
	}

	return result, nil
}

func sendClientHello(addr string, clientHello []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(clientHello)
	if err != nil {
		return nil, err
	}

	// Read all available response data
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp []byte
	buffer := make([]byte, 4096)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if n > 0 {
				resp = append(resp, buffer[:n]...)
			}
			break
		}
		resp = append(resp, buffer[:n]...)
	}

	return resp, nil
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
				handshakeLen := int(recordPayload[j+1])<<16 | int(recordPayload[j+2])<<8 | int(recordPayload[j+3])
				if j+4+handshakeLen > len(recordPayload) {
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
