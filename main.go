package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jsandas/tls-simulator/ftls"
)

const (
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384     = uint16(49192)
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384   = uint16(49188)
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       = uint16(159)
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       = uint16(107)
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA          = uint16(57)
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(52394)
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256  = uint16(196)
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA     = uint16(136)
	TLS_GOSTR341001_WITH_28147_CNT_IMIT       = uint16(129)
	TLS_RSA_WITH_AES_256_CBC_SHA256           = uint16(61)
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256      = uint16(192)
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA         = uint16(132)
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       = uint16(158)
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       = uint16(103)
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA          = uint16(51)
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256  = uint16(190)
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA     = uint16(69)
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256      = uint16(186)
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA         = uint16(65)
	TLS_RSA_WITH_RC4_128_MD5                  = uint16(4)
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA     = uint16(49160)
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA         = uint16(22)
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV         = uint16(255)
)

func main() {

	// fmt.Println(dicttls.DictCipherSuiteValueIndexed[uTlsConn.ConnectionState().CipherSuite])
	ciphers := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		TLS_GOSTR341001_WITH_28147_CNT_IMIT,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_256_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		TLS_RSA_WITH_RC4_128_MD5,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}

	clientMsg := ftls.ClientHelloMsg{
		Vers:               tls.VersionTLS13,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{ftls.CompressionNone},
		ServerName:         "localhost",
		SessionId:          []byte{},
		Random: []byte{0x3a, 0x6e, 0x72, 0xcc, 0xf9, 0x3b, 0x29, 0xbb, 0xfb, 0x2d, 0xd0, 0xa3,
			0x2b, 0x76, 0x3a, 0x9d, 0x28, 0x89, 0x11, 0xae, 0xfe, 0x4f, 0xf, 0x37, 0x6d,
			0xce, 0xa0, 0x4a, 0xf, 0x8d, 0x6e, 0x15},
		// SupportedVersions:  []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10},
		SupportedPoints: []uint8{ftls.PointFormatUncompressed},
		SupportedCurves: []ftls.CurveID{ftls.X25519, ftls.CurveP256, ftls.CurveP384, ftls.CurveP521},
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
				Group: ftls.CurveID(ftls.X25519),
				Data:  []byte{0xed, 0x7, 0xea, 0x17, 0xf2, 0x33, 0x83, 0x69, 0x5, 0x94, 0x89, 0xc7, 0x9f, 0x57, 0x19, 0xcd, 0x6b, 0xcb, 0xe7, 0x22, 0x3d, 0xb1, 0x1b, 0x8b, 0xe1, 0x52, 0x1d, 0xc2, 0x49, 0x48, 0xe4, 0x3d},
			},
		},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}

	clientHello, err := clientMsg.MarshalMsg(false)
	if err != nil {
		panic(err)
	}

	// Wrap the handshake message in a TLS record
	tlsRecord := make([]byte, 5+len(clientHello))
	tlsRecord[0] = 0x16                                                  // Handshake record type
	tlsRecord[1] = 0x03                                                  // TLS version major
	tlsRecord[2] = 0x03                                                  // TLS version minor
	binary.BigEndian.PutUint16(tlsRecord[3:5], uint16(len(clientHello))) // Record length
	copy(tlsRecord[5:], clientHello)                                     // Handshake data

	resp, err := sendClientHello("localhost:443", tlsRecord)
	if err != nil {
		fmt.Println("Handshake failed:", err)
	}

	serverHelloBytes, serverKeyExchangeBytes, err := getHandshakeMessages(resp)
	if err != nil {
		fmt.Println("Failed to get handshake messages:", err)
		return
	}

	serverHello := ftls.ServerHelloMsg{}
	// Parse ServerHello if available
	if serverHelloBytes != nil {
		// serverHello := ftls.ServerHelloMsg{}
		success := serverHello.Unmarshal(serverHelloBytes)
		if !success {
			fmt.Println("Failed to unmarshal ServerHello")
			log.Panic()
		}
		// else {
		// 	fmt.Printf("ServerHello:\n%+v\n", serverHello)
		// }
	}

	// Parse ServerKeyExchange if available
	if serverKeyExchangeBytes != nil {
		serverKeyExchange := ftls.ServerKeyExchangeMsg{}
		b3 := serverKeyExchange.Unmarshal(serverKeyExchangeBytes)
		if !b3 {
			fmt.Println("Failed to unmarshal ServerKeyExchange")
		} else {
			// fmt.Printf("ServerKeyExchange:\n%+v\n", serverKeyExchange)

			// Parse the key exchange data to identify key type and size
			err := serverKeyExchange.GetKey()
			if err != nil {
				fmt.Printf("Failed to parse ServerKeyExchange: %v\n", err)
			} else {
				serverHello.ServerShare.Group = serverKeyExchange.CurveID
				serverHello.ServerShare.Name = serverKeyExchange.KeyType
				// serverHello.ServerShare.Data = serverKeyExchange.Key
				fmt.Printf("Key Analysis:\n")
				fmt.Printf("  Type: %s\n", serverKeyExchange.KeyType)
				fmt.Printf("  Size: %d bytes\n", serverKeyExchange.KeySize)
				if serverHello.ServerShare.Group != 0 {
					fmt.Printf("  Curve ID: 0x%04x\n", serverHello.ServerShare.Group)
				}
			}
		}
	}

	fmt.Printf("ServerHello:\n%+v\n", serverHello)
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

func getHandshakeMessages(data []byte) (serverHello []byte, serverKeyExchange []byte, err error) {
	i := 0
	for i+5 <= len(data) {
		// Parse TLS record header
		contentType := data[i]
		version := binary.BigEndian.Uint16(data[i+1 : i+3])
		length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if i+5+length > len(data) {
			break // Malformed record
		}
		recordPayload := data[i+5 : i+5+length]
		fmt.Printf("TLS Record: type=0x%02x, version=0x%04x, length=%d\n", contentType, version, length)

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

				fmt.Printf("  Handshake message: type=0x%02x, length=%d\n", handshakeType, handshakeLen)

				switch handshakeType {
				case ftls.TypeServerHello:
					if serverHello == nil {
						serverHello = handshakeMessage
						fmt.Printf("    Found ServerHello\n")
					}
				case ftls.TypeServerKeyExchange:
					if serverKeyExchange == nil {
						serverKeyExchange = handshakeMessage
						fmt.Printf("    Found ServerKeyExchange\n")
					}
				case ftls.TypeCertificate:
					fmt.Printf("    Found Certificate\n")
				case ftls.TypeServerHelloDone:
					fmt.Printf("    Found ServerHelloDone\n")
				default:
					fmt.Printf("    Found other handshake message type: 0x%02x\n", handshakeType)
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
