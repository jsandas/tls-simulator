package ftls

// TLS handshake message types.
const (
	TypeHelloRequest        uint8 = 0
	TypeClientHello         uint8 = 1
	TypeServerHello         uint8 = 2
	TypeNewSessionTicket    uint8 = 4
	TypeEndOfEarlyData      uint8 = 5
	TypeEncryptedExtensions uint8 = 8
	TypeCertificate         uint8 = 11
	TypeServerKeyExchange   uint8 = 12
	TypeCertificateRequest  uint8 = 13
	TypeServerHelloDone     uint8 = 14
	TypeCertificateVerify   uint8 = 15
	TypeClientKeyExchange   uint8 = 16
	TypeFinished            uint8 = 20
	TypeCertificateStatus   uint8 = 22
	TypeKeyUpdate           uint8 = 24
	TypeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	CompressionNone uint8 = 0
)

// TLS extension numbers
const (
	ExtensionServerName              uint16 = 0
	ExtensionStatusRequest           uint16 = 5
	ExtensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	ExtensionSupportedPoints         uint16 = 11
	ExtensionSignatureAlgorithms     uint16 = 13
	ExtensionALPN                    uint16 = 16
	ExtensionSCT                     uint16 = 18
	ExtensionExtendedMasterSecret    uint16 = 23
	ExtensionSessionTicket           uint16 = 35
	ExtensionPreSharedKey            uint16 = 41
	ExtensionEarlyData               uint16 = 42
	ExtensionSupportedVersions       uint16 = 43
	ExtensionCookie                  uint16 = 44
	ExtensionPSKModes                uint16 = 45
	ExtensionCertificateAuthorities  uint16 = 47
	ExtensionSignatureAlgorithmsCert uint16 = 50
	ExtensionKeyShare                uint16 = 51
	ExtensionQUICTransportParameters uint16 = 57
	ExtensionRenegotiationInfo       uint16 = 0xff01
	ExtensionECHOuterExtensions      uint16 = 0xfd00
	ExtensionEncryptedClientHello    uint16 = 0xfe0d
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for a key exchange mechanism. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.2, this registry used to support only elliptic curves. In TLS 1.3,
// it was extended to other groups and renamed NamedGroup. See RFC 8446, Section
// 4.2.7. It was then also extended to other mechanisms, such as hybrid
// post-quantum KEMs.
type CurveID uint16

const (
	CurveP256      CurveID = 23
	CurveP384      CurveID = 24
	CurveP521      CurveID = 25
	X25519         CurveID = 29
	DH1024         CurveID = 255 // 1024-bit not in RFC 7919
	DH2048         CurveID = 256 // 2048-bit ffdhe2048, RFC 7919
	DH3072         CurveID = 257 // 3072-bit ffdhe3072, RFC 7919
	DH4096         CurveID = 258 // 4096-bit ffdhe4096, RFC 7919
	DH6144         CurveID = 259 // 6144-bit ffdhe6144, RFC 7919
	DH8192         CurveID = 260 // 8192-bit ffdhe8192, RFC 7919
	X25519MLKEM768 CurveID = 4588
)

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type PskIdentity struct {
	Label               []byte
	ObfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	PointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	StatusTypeOCSP uint8 = 1
)

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	SignaturePKCS1v15 uint8 = iota + 225
	SignatureRSAPSS
	SignatureECDSA
	SignatureEd25519
)

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203
)

// type HandshakeMessage interface {
// 	Marshal() ([]byte, error)
// 	Unmarshal([]byte) bool
// }
