package sslLabsClientSupport
//go:generate go run $GOPATH/src/github.com/mozilla/tls-observatory/tools/extractCiphersuites.go sslLabsClientSupport
var OpenSSLCiphersuites = `{
	"AES128-GCM-SHA256": {
		"iana_name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "TLS_RSA_AES_128_GCM_SHA256",
		"nss_name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 156
	},
	"AES128-SHA": {
		"iana_name": "TLS_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_RSA_AES_128_CBC_SHA1",
		"nss_name": "TLS_RSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 47
	},
	"AES128-SHA256": {
		"iana_name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "TLS_RSA_AES_128_CBC_SHA256",
		"nss_name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 60
	},
	"AES256-GCM-SHA384": {
		"iana_name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "TLS_RSA_AES_256_GCM_SHA384",
		"nss_name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 157
	},
	"AES256-SHA": {
		"iana_name": "TLS_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_RSA_AES_256_CBC_SHA1",
		"nss_name": "TLS_RSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 53
	},
	"AES256-SHA256": {
		"iana_name": "TLS_RSA_WITH_AES_256_CBC_SHA256",
		"gnutls_name": "TLS_RSA_AES_256_CBC_SHA256",
		"nss_name": "TLS_RSA_WITH_AES_256_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA256",
		"code": 61
	},
	"CAMELLIA128-SHA": {
		"iana_name": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"gnutls_name": "TLS_RSA_CAMELLIA_128_CBC_SHA1",
		"nss_name": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA1",
		"code": 65
	},
	"CAMELLIA128-SHA256": {
		"iana_name": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "TLS_RSA_CAMELLIA_128_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 186
	},
	"CAMELLIA256-SHA": {
		"iana_name": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"gnutls_name": "TLS_RSA_CAMELLIA_256_CBC_SHA1",
		"nss_name": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA1",
		"code": 132
	},
	"CAMELLIA256-SHA256": {
		"iana_name": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"gnutls_name": "TLS_RSA_CAMELLIA_256_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA256",
		"code": 192
	},
	"DES-CBC3-SHA": {
		"iana_name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_RSA_3DES_EDE_CBC_SHA1",
		"nss_name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 10
	},
	"DH-DSS-AES128-GCM-SHA256": {
		"iana_name": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 164
	},
	"DH-DSS-AES128-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 48
	},
	"DH-DSS-AES128-SHA256": {
		"iana_name": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 62
	},
	"DH-DSS-AES256-GCM-SHA384": {
		"iana_name": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 165
	},
	"DH-DSS-AES256-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 54
	},
	"DH-DSS-AES256-SHA256": {
		"iana_name": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA256",
		"code": 104
	},
	"DH-DSS-CAMELLIA128-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA1",
		"code": 66
	},
	"DH-DSS-CAMELLIA128-SHA256": {
		"iana_name": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 187
	},
	"DH-DSS-CAMELLIA256-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA1",
		"code": 133
	},
	"DH-DSS-CAMELLIA256-SHA256": {
		"iana_name": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA256",
		"code": 193
	},
	"DH-DSS-DES-CBC3-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 13
	},
	"DH-DSS-SEED-SHA": {
		"iana_name": "TLS_DH_DSS_WITH_SEED_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "DH/DSS",
		"au": "DH",
		"encryption": {
			"cipher": "SEED",
			"key": 128
		},
		"mac": "SHA1",
		"code": 151
	},
	"DH-RSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 160
	},
	"DH-RSA-AES128-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49
	},
	"DH-RSA-AES128-SHA256": {
		"iana_name": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 63
	},
	"DH-RSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 161
	},
	"DH-RSA-AES256-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 55
	},
	"DH-RSA-AES256-SHA256": {
		"iana_name": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA256",
		"code": 105
	},
	"DH-RSA-CAMELLIA128-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA1",
		"code": 67
	},
	"DH-RSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 188
	},
	"DH-RSA-CAMELLIA256-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA1",
		"code": 134
	},
	"DH-RSA-CAMELLIA256-SHA256": {
		"iana_name": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA256",
		"code": 194
	},
	"DH-RSA-DES-CBC3-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 16
	},
	"DH-RSA-SEED-SHA": {
		"iana_name": "TLS_DH_RSA_WITH_SEED_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "DH/RSA",
		"au": "DH",
		"encryption": {
			"cipher": "SEED",
			"key": 128
		},
		"mac": "SHA1",
		"code": 152
	},
	"DHE-DSS-AES128-GCM-SHA256": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "TLS_DHE_DSS_AES_128_GCM_SHA256",
		"nss_name": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 162
	},
	"DHE-DSS-AES128-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_DHE_DSS_AES_128_CBC_SHA1",
		"nss_name": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 50
	},
	"DHE-DSS-AES128-SHA256": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "TLS_DHE_DSS_AES_128_CBC_SHA256",
		"nss_name": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 64
	},
	"DHE-DSS-AES256-GCM-SHA384": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "TLS_DHE_DSS_AES_256_GCM_SHA384",
		"nss_name": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 163
	},
	"DHE-DSS-AES256-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_DHE_DSS_AES_256_CBC_SHA1",
		"nss_name": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 56
	},
	"DHE-DSS-AES256-SHA256": {
		"iana_name": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		"gnutls_name": "TLS_DHE_DSS_AES_256_CBC_SHA256",
		"nss_name": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA256",
		"code": 106
	},
	"DHE-DSS-CAMELLIA128-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"gnutls_name": "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1",
		"nss_name": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA1",
		"code": 68
	},
	"DHE-DSS-CAMELLIA128-SHA256": {
		"iana_name": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 189
	},
	"DHE-DSS-CAMELLIA256-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"gnutls_name": "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1",
		"nss_name": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA1",
		"code": 135
	},
	"DHE-DSS-CAMELLIA256-SHA256": {
		"iana_name": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		"gnutls_name": "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA256",
		"code": 195
	},
	"DHE-DSS-RC4-SHA": {
		"iana_name": "",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 102
	},
	"DHE-DSS-SEED-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "SEED",
			"key": 128
		},
		"mac": "SHA1",
		"code": 153
	},
	"DHE-RSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "TLS_DHE_RSA_AES_128_GCM_SHA256",
		"nss_name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 158
	},
	"DHE-RSA-AES128-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_DHE_RSA_AES_128_CBC_SHA1",
		"nss_name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 51
	},
	"DHE-RSA-AES128-SHA256": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "TLS_DHE_RSA_AES_128_CBC_SHA256",
		"nss_name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 103
	},
	"DHE-RSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "TLS_DHE_RSA_AES_256_GCM_SHA384",
		"nss_name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 159
	},
	"DHE-RSA-AES256-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_DHE_RSA_AES_256_CBC_SHA1",
		"nss_name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 57
	},
	"DHE-RSA-AES256-SHA256": {
		"iana_name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"gnutls_name": "TLS_DHE_RSA_AES_256_CBC_SHA256",
		"nss_name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA256",
		"code": 107
	},
	"DHE-RSA-CAMELLIA128-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"gnutls_name": "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1",
		"nss_name": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA1",
		"code": 69
	},
	"DHE-RSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 190
	},
	"DHE-RSA-CAMELLIA256-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"gnutls_name": "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1",
		"nss_name": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA1",
		"code": 136
	},
	"DHE-RSA-CAMELLIA256-SHA256": {
		"iana_name": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"gnutls_name": "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA256",
		"code": 196
	},
	"DHE-RSA-CHACHA20-POLY1305-OLD": {
		"iana_name": "",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "ChaCha20",
			"key": 256
		},
		"mac": "AEAD",
		"code": 52245
	},
	"DHE-RSA-SEED-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "SEED",
			"key": 128
		},
		"mac": "SHA1",
		"code": 154
	},
	"ECDH-ECDSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 49197
	},
	"ECDH-ECDSA-AES128-SHA": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49156
	},
	"ECDH-ECDSA-AES128-SHA256": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49189
	},
	"ECDH-ECDSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 49198
	},
	"ECDH-ECDSA-AES256-SHA": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49157
	},
	"ECDH-ECDSA-AES256-SHA384": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49190
	},
	"ECDH-ECDSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49268
	},
	"ECDH-ECDSA-CAMELLIA256-SHA384": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49269
	},
	"ECDH-ECDSA-DES-CBC3-SHA": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49155
	},
	"ECDH-ECDSA-RC4-SHA": {
		"iana_name": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/ECDSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49154
	},
	"ECDH-RSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 49201
	},
	"ECDH-RSA-AES128-SHA": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49166
	},
	"ECDH-RSA-AES128-SHA256": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49193
	},
	"ECDH-RSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 49202
	},
	"ECDH-RSA-AES256-SHA": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49167
	},
	"ECDH-RSA-AES256-SHA384": {
		"iana_name": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49194
	},
	"ECDH-RSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49272
	},
	"ECDH-RSA-CAMELLIA256-SHA384": {
		"iana_name": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49273
	},
	"ECDH-RSA-DES-CBC3-SHA": {
		"iana_name": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49165
	},
	"ECDH-RSA-RC4-SHA": {
		"iana_name": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
		"proto": "SSLv3",
		"kx": "ECDH/RSA",
		"au": "ECDH",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49164
	},
	"ECDHE-ECDSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 49195
	},
	"ECDHE-ECDSA-AES128-SHA": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_128_CBC_SHA1",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49161
	},
	"ECDHE-ECDSA-AES128-SHA256": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_128_CBC_SHA256",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49187
	},
	"ECDHE-ECDSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 49196
	},
	"ECDHE-ECDSA-AES256-SHA": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_256_CBC_SHA1",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49162
	},
	"ECDHE-ECDSA-AES256-SHA384": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"gnutls_name": "TLS_ECDHE_ECDSA_AES_256_CBC_SHA384",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49188
	},
	"ECDHE-ECDSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "TLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49266
	},
	"ECDHE-ECDSA-CAMELLIA256-SHA384": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		"gnutls_name": "TLS_ECDHE_ECDSA_CAMELLIA_256_CBC_SHA384",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49267
	},
	"ECDHE-ECDSA-CHACHA20-POLY1305-OLD": {
		"iana_name": "",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "ChaCha20",
			"key": 256
		},
		"mac": "AEAD",
		"code": 52244
	},
	"ECDHE-ECDSA-DES-CBC3-SHA": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA1",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49160
	},
	"ECDHE-ECDSA-RC4-SHA": {
		"iana_name": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"gnutls_name": "TLS_ECDHE_ECDSA_ARCFOUR_128_SHA1",
		"nss_name": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "ECDSA",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49159
	},
	"ECDHE-RSA-AES128-GCM-SHA256": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"gnutls_name": "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 128
		},
		"mac": "AEAD",
		"code": 49199
	},
	"ECDHE-RSA-AES128-SHA": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_RSA_AES_128_CBC_SHA1",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49171
	},
	"ECDHE-RSA-AES128-SHA256": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"gnutls_name": "TLS_ECDHE_RSA_AES_128_CBC_SHA256",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49191
	},
	"ECDHE-RSA-AES256-GCM-SHA384": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"gnutls_name": "TLS_ECDHE_RSA_AES_256_GCM_SHA384",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AESGCM",
			"key": 256
		},
		"mac": "AEAD",
		"code": 49200
	},
	"ECDHE-RSA-AES256-SHA": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_RSA_AES_256_CBC_SHA1",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49172
	},
	"ECDHE-RSA-AES256-SHA384": {
		"iana_name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"gnutls_name": "TLS_ECDHE_RSA_AES_256_CBC_SHA384",
		"nss_name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49192
	},
	"ECDHE-RSA-CAMELLIA128-SHA256": {
		"iana_name": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"gnutls_name": "TLS_ECDHE_RSA_CAMELLIA_128_CBC_SHA256",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 128
		},
		"mac": "SHA256",
		"code": 49270
	},
	"ECDHE-RSA-CAMELLIA256-SHA384": {
		"iana_name": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		"gnutls_name": "TLS_ECDHE_RSA_CAMELLIA_256_CBC_SHA384",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "Camellia",
			"key": 256
		},
		"mac": "SHA384",
		"code": 49271
	},
	"ECDHE-RSA-CHACHA20-POLY1305-OLD": {
		"iana_name": "",
		"gnutls_name": "",
		"nss_name": "",
		"proto": "TLSv1.2",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "ChaCha20",
			"key": 256
		},
		"mac": "AEAD",
		"code": 52243
	},
	"ECDHE-RSA-DES-CBC3-SHA": {
		"iana_name": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1",
		"nss_name": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49170
	},
	"ECDHE-RSA-RC4-SHA": {
		"iana_name": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"gnutls_name": "TLS_ECDHE_RSA_ARCFOUR_128_SHA1",
		"nss_name": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"proto": "SSLv3",
		"kx": "ECDH",
		"au": "RSA",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49169
	},
	"EDH-DSS-DES-CBC3-SHA": {
		"iana_name": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_DHE_DSS_3DES_EDE_CBC_SHA1",
		"nss_name": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "DSS",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 19
	},
	"EDH-RSA-DES-CBC3-SHA": {
		"iana_name": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_DHE_RSA_3DES_EDE_CBC_SHA1",
		"nss_name": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"proto": "SSLv3",
		"kx": "DH",
		"au": "RSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 22
	},
	"IDEA-CBC-SHA": {
		"iana_name": "TLS_RSA_WITH_IDEA_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_RSA_WITH_IDEA_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "IDEA",
			"key": 128
		},
		"mac": "SHA1",
		"code": 7
	},
	"PSK-3DES-EDE-CBC-SHA": {
		"iana_name": "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_PSK_3DES_EDE_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "PSK",
		"au": "PSK",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 139
	},
	"PSK-AES128-CBC-SHA": {
		"iana_name": "TLS_PSK_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_PSK_AES_128_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "PSK",
		"au": "PSK",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 140
	},
	"PSK-AES256-CBC-SHA": {
		"iana_name": "TLS_PSK_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_PSK_AES_256_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "PSK",
		"au": "PSK",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 141
	},
	"PSK-RC4-SHA": {
		"iana_name": "TLS_PSK_WITH_RC4_128_SHA",
		"gnutls_name": "TLS_PSK_ARCFOUR_128_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "PSK",
		"au": "PSK",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 138
	},
	"RC4-MD5": {
		"iana_name": "TLS_RSA_WITH_RC4_128_MD5",
		"gnutls_name": "TLS_RSA_ARCFOUR_128_MD5",
		"nss_name": "TLS_RSA_WITH_RC4_128_MD5",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "MD5",
		"code": 4
	},
	"RC4-SHA": {
		"iana_name": "TLS_RSA_WITH_RC4_128_SHA",
		"gnutls_name": "TLS_RSA_ARCFOUR_128_SHA1",
		"nss_name": "TLS_RSA_WITH_RC4_128_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 5
	},
	"RSA-PSK-3DES-EDE-CBC-SHA": {
		"iana_name": "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_RSA_PSK_3DES_EDE_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "RSAPSK",
		"au": "RSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 147
	},
	"RSA-PSK-AES128-CBC-SHA": {
		"iana_name": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_RSA_PSK_AES_128_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "RSAPSK",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 148
	},
	"RSA-PSK-AES256-CBC-SHA": {
		"iana_name": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_RSA_PSK_AES_256_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "RSAPSK",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 149
	},
	"RSA-PSK-RC4-SHA": {
		"iana_name": "TLS_RSA_PSK_WITH_RC4_128_SHA",
		"gnutls_name": "TLS_RSA_PSK_ARCFOUR_128_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "RSAPSK",
		"au": "RSA",
		"encryption": {
			"cipher": "RC4",
			"key": 128
		},
		"mac": "SHA1",
		"code": 146
	},
	"SEED-SHA": {
		"iana_name": "TLS_RSA_WITH_SEED_CBC_SHA",
		"gnutls_name": "",
		"nss_name": "TLS_RSA_WITH_SEED_CBC_SHA",
		"proto": "SSLv3",
		"kx": "RSA",
		"au": "RSA",
		"encryption": {
			"cipher": "SEED",
			"key": 128
		},
		"mac": "SHA1",
		"code": 150
	},
	"SRP-3DES-EDE-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_3DES_EDE_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "SRP",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49178
	},
	"SRP-AES-128-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_AES_128_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "SRP",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49181
	},
	"SRP-AES-256-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_AES_256_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "SRP",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49184
	},
	"SRP-DSS-3DES-EDE-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "DSS",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49180
	},
	"SRP-DSS-AES-128-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_DSS_AES_128_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49183
	},
	"SRP-DSS-AES-256-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_DSS_AES_256_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "DSS",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49186
	},
	"SRP-RSA-3DES-EDE-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "RSA",
		"encryption": {
			"cipher": "3DES",
			"key": 168
		},
		"mac": "SHA1",
		"code": 49179
	},
	"SRP-RSA-AES-128-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_RSA_AES_128_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 128
		},
		"mac": "SHA1",
		"code": 49182
	},
	"SRP-RSA-AES-256-CBC-SHA": {
		"iana_name": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
		"gnutls_name": "TLS_SRP_SHA_RSA_AES_256_CBC_SHA1",
		"nss_name": "",
		"proto": "SSLv3",
		"kx": "SRP",
		"au": "RSA",
		"encryption": {
			"cipher": "AES",
			"key": 256
		},
		"mac": "SHA1",
		"code": 49185
	}
}`