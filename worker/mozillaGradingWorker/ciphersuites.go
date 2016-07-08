package mozillaGradingWorker

var OpenSSLCiphersuites = `{
"AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"AES128-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"AES256-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"AES256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA256"
},
"CAMELLIA128-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA1"
},
"CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"CAMELLIA256-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA1"
},
"CAMELLIA256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA256"
},
"DES-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "DES",
		"key": 56
	},
	"mac": "SHA1"
},
"DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"DH-DSS-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"DH-DSS-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"DH-DSS-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"DH-DSS-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"DH-DSS-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"DH-DSS-AES256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA256"
},
"DH-DSS-CAMELLIA128-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA1"
},
"DH-DSS-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"DH-DSS-CAMELLIA256-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA1"
},
"DH-DSS-CAMELLIA256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA256"
},
"DH-DSS-DES-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "DES",
		"key": 56
	},
	"mac": "SHA1"
},
"DH-DSS-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"DH-DSS-SEED-SHA": {
	"proto": "SSLv3",
	"kx": "DH/DSS",
	"au": "DH",
	"encryption": {
		"cipher": "SEED",
		"key": 128
	},
	"mac": "SHA1"
},
"DH-RSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"DH-RSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"DH-RSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"DH-RSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"DH-RSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"DH-RSA-AES256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA256"
},
"DH-RSA-CAMELLIA128-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA1"
},
"DH-RSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"DH-RSA-CAMELLIA256-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA1"
},
"DH-RSA-CAMELLIA256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA256"
},
"DH-RSA-DES-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "DES",
		"key": 56
	},
	"mac": "SHA1"
},
"DH-RSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"DH-RSA-SEED-SHA": {
	"proto": "SSLv3",
	"kx": "DH/RSA",
	"au": "DH",
	"encryption": {
		"cipher": "SEED",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-DSS-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"DHE-DSS-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-DSS-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"DHE-DSS-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"DHE-DSS-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"DHE-DSS-AES256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA256"
},
"DHE-DSS-CAMELLIA128-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-DSS-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"DHE-DSS-CAMELLIA256-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA1"
},
"DHE-DSS-CAMELLIA256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA256"
},
"DHE-DSS-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-DSS-SEED-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "SEED",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-RSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"DHE-RSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-RSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"DHE-RSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"DHE-RSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"DHE-RSA-AES256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA256"
},
"DHE-RSA-CAMELLIA128-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA1"
},
"DHE-RSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"DHE-RSA-CAMELLIA256-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA1"
},
"DHE-RSA-CAMELLIA256-SHA256": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA256"
},
"DHE-RSA-CHACHA20-POLY1305": {
	"proto": "TLSv1.2",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "ChaCha20",
		"key": 256
	},
	"mac": "AEAD"
},
"DHE-RSA-SEED-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "SEED",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDH-ECDSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"ECDH-ECDSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDH-ECDSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDH-ECDSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDH-ECDSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"ECDH-ECDSA-AES256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDH-ECDSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDH-ECDSA-CAMELLIA256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDH-ECDSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"ECDH-ECDSA-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/ECDSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDH-RSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"ECDH-RSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDH-RSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDH-RSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDH-RSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"ECDH-RSA-AES256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDH-RSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDH-RSA-CAMELLIA256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDH-RSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"ECDH-RSA-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH/RSA",
	"au": "ECDH",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDHE-ECDSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"ECDHE-ECDSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDHE-ECDSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDHE-ECDSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDHE-ECDSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"ECDHE-ECDSA-AES256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDHE-ECDSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDHE-ECDSA-CAMELLIA256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDHE-ECDSA-CHACHA20-POLY1305": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "ChaCha20",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDHE-ECDSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"ECDHE-ECDSA-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "ECDSA",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDHE-RSA-AES128-GCM-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 128
	},
	"mac": "AEAD"
},
"ECDHE-RSA-AES128-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"ECDHE-RSA-AES128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDHE-RSA-AES256-GCM-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AESGCM",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDHE-RSA-AES256-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"ECDHE-RSA-AES256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDHE-RSA-CAMELLIA128-SHA256": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 128
	},
	"mac": "SHA256"
},
"ECDHE-RSA-CAMELLIA256-SHA384": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "Camellia",
		"key": 256
	},
	"mac": "SHA384"
},
"ECDHE-RSA-CHACHA20-POLY1305": {
	"proto": "TLSv1.2",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "ChaCha20",
		"key": 256
	},
	"mac": "AEAD"
},
"ECDHE-RSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"ECDHE-RSA-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "ECDH",
	"au": "RSA",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"EDH-DSS-DES-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "DES",
		"key": 56
	},
	"mac": "SHA1"
},
"EDH-DSS-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "DSS",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"EDH-RSA-DES-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "DES",
		"key": 56
	},
	"mac": "SHA1"
},
"EDH-RSA-DES-CBC3-SHA": {
	"proto": "SSLv3",
	"kx": "DH",
	"au": "RSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"IDEA-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "IDEA",
		"key": 128
	},
	"mac": "SHA1"
},
"PSK-3DES-EDE-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "PSK",
	"au": "PSK",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"PSK-AES128-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "PSK",
	"au": "PSK",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"PSK-AES256-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "PSK",
	"au": "PSK",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"PSK-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "PSK",
	"au": "PSK",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"RC4-MD5": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "MD5"
},
"RC4-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"RSA-PSK-3DES-EDE-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "RSAPSK",
	"au": "RSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"RSA-PSK-AES128-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "RSAPSK",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"RSA-PSK-AES256-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "RSAPSK",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"RSA-PSK-RC4-SHA": {
	"proto": "SSLv3",
	"kx": "RSAPSK",
	"au": "RSA",
	"encryption": {
		"cipher": "RC4",
		"key": 128
	},
	"mac": "SHA1"
},
"SEED-SHA": {
	"proto": "SSLv3",
	"kx": "RSA",
	"au": "RSA",
	"encryption": {
		"cipher": "SEED",
		"key": 128
	},
	"mac": "SHA1"
},
"SRP-3DES-EDE-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "SRP",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"SRP-AES-128-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "SRP",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"SRP-AES-256-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "SRP",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"SRP-DSS-3DES-EDE-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "DSS",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"SRP-DSS-AES-128-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"SRP-DSS-AES-256-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "DSS",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
},
"SRP-RSA-3DES-EDE-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "RSA",
	"encryption": {
		"cipher": "3DES",
		"key": 168
	},
	"mac": "SHA1"
},
"SRP-RSA-AES-128-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 128
	},
	"mac": "SHA1"
},
"SRP-RSA-AES-256-CBC-SHA": {
	"proto": "SSLv3",
	"kx": "SRP",
	"au": "RSA",
	"encryption": {
		"cipher": "AES",
		"key": 256
	},
	"mac": "SHA1"
}
}`
