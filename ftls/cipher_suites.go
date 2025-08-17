// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ftls

var DefaultCipherSuites = []uint16{
	// AEADs w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// CBC w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

	// AEADs w/o ECDHE
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,

	// CBC w/o ECDHE
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,

	// 3DES
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,

	// CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,

	// RC4
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
var DefaultCipherSuitesTLS13 = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
}

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_NULL_MD5                             uint16 = 0x0001
	TLS_RSA_WITH_NULL_SHA                             uint16 = 0x0002
	TLS_RSA_EXPORT_WITH_RC4_40_MD5                    uint16 = 0x0003
	TLS_RSA_WITH_RC4_128_MD5                          uint16 = 0x0004
	TLS_RSA_WITH_RC4_128_SHA                          uint16 = 0x0005
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5                uint16 = 0x0006
	TLS_RSA_WITH_IDEA_CBC_SHA                         uint16 = 0x0007
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA                 uint16 = 0x0008
	TLS_RSA_WITH_DES_CBC_SHA                          uint16 = 0x0009
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                     uint16 = 0x000a
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA              uint16 = 0x000b
	TLS_DH_DSS_WITH_DES_CBC_SHA                       uint16 = 0x000c
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA                  uint16 = 0x000d
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA              uint16 = 0x000e
	TLS_DH_RSA_WITH_DES_CBC_SHA                       uint16 = 0x000f
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                  uint16 = 0x0010
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA             uint16 = 0x0011
	TLS_DHE_DSS_WITH_DES_CBC_SHA                      uint16 = 0x0012
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x0013
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA             uint16 = 0x0014
	TLS_DHE_RSA_WITH_DES_CBC_SHA                      uint16 = 0x0015
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x0016
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5                uint16 = 0x0017
	TLS_DH_anon_WITH_RC4_128_MD5                      uint16 = 0x0018
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA             uint16 = 0x0019
	TLS_DH_anon_WITH_DES_CBC_SHA                      uint16 = 0x001a
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x001b
	TLS_RSA_WITH_AES_128_CBC_SHA                      uint16 = 0x002f
	TLS_DH_DSS_WITH_AES_128_CBC_SHA                   uint16 = 0x0030
	TLS_DH_RSA_WITH_AES_128_CBC_SHA                   uint16 = 0x0031
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA                  uint16 = 0x0032
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x0033
	TLS_DH_anon_WITH_AES_128_CBC_SHA                  uint16 = 0x0034
	TLS_RSA_WITH_AES_256_CBC_SHA                      uint16 = 0x0035
	TLS_DH_DSS_WITH_AES_256_CBC_SHA                   uint16 = 0x0036
	TLS_DH_RSA_WITH_AES_256_CBC_SHA                   uint16 = 0x0037
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA                  uint16 = 0x0038
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0039
	TLS_DH_anon_WITH_AES_256_CBC_SHA                  uint16 = 0x003a
	TLS_RSA_WITH_NULL_SHA256                          uint16 = 0x003b
	TLS_RSA_WITH_AES_128_CBC_SHA256                   uint16 = 0x003c
	TLS_RSA_WITH_AES_256_CBC_SHA256                   uint16 = 0x003d
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256                uint16 = 0x003e
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256                uint16 = 0x003f
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256               uint16 = 0x0040
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA                 uint16 = 0x0041
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA              uint16 = 0x0042
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA              uint16 = 0x0043
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA             uint16 = 0x0044
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA             uint16 = 0x0045
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA             uint16 = 0x0046
	TLS_RSA_EXPORT1024_WITH_RC4_56_MD5                uint16 = 0x0060
	TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5            uint16 = 0x0061
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA               uint16 = 0x0062
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA           uint16 = 0x0063
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA                uint16 = 0x0064
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA            uint16 = 0x0065
	TLS_DHE_DSS_WITH_RC4_128_SHA                      uint16 = 0x0066
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x0067
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256                uint16 = 0x0068
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256                uint16 = 0x0069
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256               uint16 = 0x006a
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256               uint16 = 0x006b
	TLS_DH_anon_WITH_AES_128_CBC_SHA256               uint16 = 0x006c
	TLS_DH_anon_WITH_AES_256_CBC_SHA256               uint16 = 0x006d
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA                 uint16 = 0x0084
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA              uint16 = 0x0085
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA              uint16 = 0x0086
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA             uint16 = 0x0087
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA             uint16 = 0x0088
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA             uint16 = 0x0089
	TLS_PSK_WITH_RC4_128_SHA                          uint16 = 0x008a
	TLS_PSK_WITH_3DES_EDE_CBC_SHA                     uint16 = 0x008b
	TLS_PSK_WITH_AES_128_CBC_SHA                      uint16 = 0x008c
	TLS_PSK_WITH_AES_256_CBC_SHA                      uint16 = 0x008d
	TLS_RSA_PSK_WITH_RC4_128_SHA                      uint16 = 0x0092
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x0093
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA                  uint16 = 0x0094
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA                  uint16 = 0x0095
	TLS_RSA_WITH_SEED_CBC_SHA                         uint16 = 0x0096
	TLS_DH_DSS_WITH_SEED_CBC_SHA                      uint16 = 0x0097
	TLS_DH_RSA_WITH_SEED_CBC_SHA                      uint16 = 0x0098
	TLS_DHE_DSS_WITH_SEED_CBC_SHA                     uint16 = 0x0099
	TLS_DHE_RSA_WITH_SEED_CBC_SHA                     uint16 = 0x009a
	TLS_DH_anon_WITH_SEED_CBC_SHA                     uint16 = 0x009b
	TLS_RSA_WITH_AES_128_GCM_SHA256                   uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384                   uint16 = 0x009d
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009e
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009f
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256                uint16 = 0x00a0
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384                uint16 = 0x00a1
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256               uint16 = 0x00a2
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384               uint16 = 0x00a3
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256                uint16 = 0x00a4
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384                uint16 = 0x00a5
	TLS_DH_anon_WITH_AES_128_GCM_SHA256               uint16 = 0x00a6
	TLS_DH_anon_WITH_AES_256_GCM_SHA384               uint16 = 0x00a7
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256              uint16 = 0x00ba
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256           uint16 = 0x00bb
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256           uint16 = 0x00bc
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256          uint16 = 0x00bd
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256          uint16 = 0x00be
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256          uint16 = 0x00bf
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256              uint16 = 0x00c0
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256           uint16 = 0x00c1
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256           uint16 = 0x00c2
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256          uint16 = 0x00c3
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256          uint16 = 0x00c4
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256          uint16 = 0x00c5
	TLS_ECDH_ECDSA_WITH_NULL_SHA                      uint16 = 0xc001
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA                   uint16 = 0xc002
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA              uint16 = 0xc003
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA               uint16 = 0xc004
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA               uint16 = 0xc005
	TLS_ECDHE_ECDSA_WITH_NULL_SHA                     uint16 = 0xc006
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA                  uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA             uint16 = 0xc008
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA              uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA              uint16 = 0xc00a
	TLS_ECDH_RSA_WITH_NULL_SHA                        uint16 = 0xc00b
	TLS_ECDH_RSA_WITH_RC4_128_SHA                     uint16 = 0xc00c
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA                uint16 = 0xc00d
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA                 uint16 = 0xc00e
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA                 uint16 = 0xc00f
	TLS_ECDHE_RSA_WITH_NULL_SHA                       uint16 = 0xc010
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                    uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA               uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                uint16 = 0xc014
	TLS_ECDH_anon_WITH_NULL_SHA                       uint16 = 0xc015
	TLS_ECDH_anon_WITH_RC4_128_SHA                    uint16 = 0xc016
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA               uint16 = 0xc017
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA                uint16 = 0xc018
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA                uint16 = 0xc019
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0xc01a
	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA             uint16 = 0xc01b
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA             uint16 = 0xc01c
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA                  uint16 = 0xc01d
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA              uint16 = 0xc01e
	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA              uint16 = 0xc01f
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA                  uint16 = 0xc020
	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA              uint16 = 0xc021
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA              uint16 = 0xc022
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256           uint16 = 0xc023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384           uint16 = 0xc024
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256            uint16 = 0xc025
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384            uint16 = 0xc026
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256             uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384             uint16 = 0xc028
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256              uint16 = 0xc029
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384              uint16 = 0xc02a
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256           uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384           uint16 = 0xc02c
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256            uint16 = 0xc02d
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384            uint16 = 0xc02e
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             uint16 = 0xc030
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256              uint16 = 0xc031
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384              uint16 = 0xc032
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256      uint16 = 0xc072
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384      uint16 = 0xc073
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256       uint16 = 0xc074
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384       uint16 = 0xc075
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256        uint16 = 0xc076
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384        uint16 = 0xc077
	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256         uint16 = 0xc078
	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384         uint16 = 0xc079
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD   uint16 = 0xcc13 // draft version of ChaCha ciphers
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD uint16 = 0xcc14 // draft version of ChaCha ciphers
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD     uint16 = 0xcc15 // draft version of ChaCha ciphers
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256       uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256     uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	TLS_AES_128_CCM_SHA256       uint16 = 0x1304
	TLS_AES_128_CCM_8_SHA256     uint16 = 0x1305

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)
