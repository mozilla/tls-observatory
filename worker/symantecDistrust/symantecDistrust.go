package symantecDistrust

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "symantecDistrust"
	workerDesc = "Checks if the target is impacted by https://wiki.mozilla.org/CA/Upcoming_Distrust_Actions"
	log        = logger.GetLogger()
)

func init() {
	runner := new(runner)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

type runner struct {
}

// SPKI hashes of blacklisted roots
var blacklist = []string{
	//   /C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
	// FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A
	"87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5",

	//   /C=US/O=GeoTrust Inc./OU=(c) 2007 GeoTrust Inc. - For authorized use only/CN=GeoTrust Primary Certification Authority - G2
	// 5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766
	"BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB",

	//   /C=US/O=GeoTrust Inc./OU=(c) 2008 GeoTrust Inc. - For authorized use only/CN=GeoTrust Primary Certification Authority - G3
	// B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4
	"AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F",

	//   /C=US/O=GeoTrust Inc./CN=GeoTrust Primary Certification Authority
	// 37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C
	"4905466623AB4178BE92AC5CBD6584F7A1E17F27652D5A85AF89504EA239AAAA",

	//   /C=US/O=GeoTrust Inc./CN=GeoTrust Universal CA
	// A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912
	"9699225C5DE52E56CDD32DF2E96D1CFEA5AA3CA0BB52CD8933C23B5C27443820",

	//   /C=US/O=GeoTrust Inc./CN=GeoTrust Universal CA 2
	// A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B
	"7CAA03465124590C601E567E52148E952C0CFFE89000530FE0D95B6D50EAAE41",

	//   /C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 1 Public Primary Certification Authority - G4
	// 363F3C849EAB03B0A2A0F636D7B86D04D3AC7FCFE26A0A9121AB9795F6E176DF
	"31512680233F5F2A1F29437F56D4988CF0AFC41CC6C5DA6275928E9C0BEADE27",

	//   /C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 1 Public Primary Certification Authority - G6
	// 9D190B2E314566685BE8A889E27AA8C7D7AE1D8AADDBA3C1ECF9D24863CD34B9
	"D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7",

	//   /C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 2 Public Primary Certification Authority - G4
	// FE863D0822FE7A2353FA484D5924E875656D3DC9FB58771F6F616F9D571BC592
	"3027A298FA57314DC0E3DD1019411B8F404C43C3F934CE3BDF856512C80AA15C",

	//   /C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 2 Public Primary Certification Authority - G6
	// CB627D18B58AD56DDE331A30456BC65C601A4E9B18DEDCEA08E7DAAA07815FF0
	"AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258",

	//   /C=US/O=thawte Inc./OU=Certification Services Division/OU=(c) 2006 thawte Inc. - For authorized use only/CN=thawte Primary Root CA
	// 8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F
	"1D75D0831B9E0885394D32C7A1BFDB3DBC1C28E2B0E8391FB135981DBC5BA936",

	//   /C=US/O=thawte Inc./OU=(c) 2007 thawte Inc. - For authorized use only/CN=thawte Primary Root CA - G2
	// A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557
	"67DC4F32FA10E7D01A79A073AA0C9E0212EC2FFC3D779E0AA7F9C0F0E1C2C893",

	//   /C=US/O=thawte Inc./OU=Certification Services Division/OU=(c) 2008 thawte Inc. - For authorized use only/CN=thawte Primary Root CA - G3
	// 4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C
	"1906C6124DBB438578D00E066D5054C6C37F0FA6028C05545E0994EDDAEC8629",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign Inc. - For authorized use only/CN=VeriSign Class 1 Public Primary Certification Authority - G3
	// CBB5AF185E942A2402F9EACBC0ED5BB876EEA3C1223623D00447E4F3BA554B65
	"22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign Inc. - For authorized use only/CN=VeriSign Class 2 Public Primary Certification Authority - G3
	// 92A9D9833FE1944DB366E8BFAE7A95B6480C2D6C6C2A1BE65D4236B608FCA1BB
	"7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G3
	// EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244
	"495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 2007 VeriSign Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G4
	// 69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79
	"5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5
	// 9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF
	"25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058",

	//   /C=US/O=VeriSign Inc./OU=VeriSign Trust Network/OU=(c) 2008 VeriSign Inc. - For authorized use only/CN=VeriSign Universal Root Certification Authority
	// 2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C
	"967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872",
}

// SPKI hashes of whitelisted intermediates
var whitelist = []string{
	// /C=US/O=Google Inc/CN=Google Internet Authority G2
	// SHA256 Fingerprint: 9B:75:9D:41:E3:DE:30:F9:D2:F9:02:02:7D:79:2B:65
	//                     D9:50:A9:8B:BB:6D:6D:56:BE:7F:25:28:45:3B:F8:E9
	// https://crt.sh/?id=142951186 (crt.sh ID=142951186)
	"EC722969CB64200AB6638F68AC538E40ABAB5B19A6485661042A1061C4612776",

	// /C=US/O=Google Inc/CN=Google Internet Authority G2
	// SHA256 Fingerprint: 9F:63:04:26:DF:1D:8A:BF:D8:0A:CE:98:87:1B:A8:33
	//                     AB:97:42:CB:34:83:8D:E2:B5:28:5E:D5:4C:0C:7D:CC
	// https://crt.sh/?id=23635000 (crt.sh ID=23635000)
	"EC722969CB64200AB6638F68AC538E40ABAB5B19A6485661042A1061C4612776",

	// /CN=Apple IST CA 2 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: AC:2B:92:2E:CF:D5:E0:17:11:77:2F:EA:8E:D3:72:DE
	//                     9D:1E:22:45:FC:E3:F5:7A:9C:DB:EC:77:29:6A:42:4B
	// https://crt.sh/?id=5250464 (crt.sh ID=5250464)
	"B5CF82D47EF9823F9AA78F123186C52E8879EA84B0F822C91D83E04279B78FD5",

	// /CN=Apple IST CA 5 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: 3D:B7:6D:1D:D7:D3:A7:59:DC:CC:3F:8F:A7:F6:86:75
	//                     C0:80:CB:09:5E:48:81:06:3A:6B:85:0F:DD:68:B8:BC
	// https://crt.sh/?id=12716200 (crt.sh ID=12716200)
	"56E98DEAC006A729AFA2ED79F9E419DF69F451242596D2AAF284C74A855E352E",

	// /CN=Apple IST CA 4 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: 61:15:F0:6A:33:8A:64:9E:61:58:52:10:E7:6F:2E:CE
	//                     39:89:BC:A6:5A:62:B0:66:04:0C:D7:C5:F4:08:ED:D0
	// https://crt.sh/?id=19602712 (crt.sh ID=19602712)
	"7289C06DEDD16B71A7DCCA66578572E2E109B11D70AD04C2601B6743BC66D07B",

	// /CN=Apple IST CA 7 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: 17:F9:66:09:AC:6A:D0:A2:D6:AB:0A:21:B2:D1:B5:B2
	//                     94:6B:D0:4D:BF:12:07:03:D1:DE:F6:FB:62:F4:B6:61
	// https://crt.sh/?id=19602724 (crt.sh ID=19602724)
	"C0554BDE87A075EC13A61F275983AE023957294B454CAF0A9724E3B21B7935BC",

	// /CN=Apple IST CA 8 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: A4:FE:7C:7F:15:15:5F:3F:0A:EF:7A:AA:83:CF:6E:06
	//                     DE:B9:7C:A3:F9:09:DF:92:0A:C1:49:08:82:D4:88:ED
	// https://crt.sh/?id=21760447 (crt.sh ID=21760447)
	"E24F8E8C2185DA2F5E88D4579E817C47BF6EAFBC8505F0F960FD5A0DF4473AD3",

	// /CN=Apple IST CA 3 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: 6D:E9:09:78:91:04:22:A8:9E:26:F2:DF:85:97:14:30
	//                     C3:F4:4C:D1:78:5D:AD:94:30:8F:7C:A4:B6:FB:E5:21
	// https://crt.sh/?id=19602706 (crt.sh ID=19602706)
	"3174D9092F9531C06026BA489891016B436D5EC02623F9AAFE2009ECC3E4D557",

	// /CN=Apple IST CA 6 - G1/OU=Certification Authority/O=Apple Inc./C=US
	// SHA256 Fingerprint: 90:4F:B5:A4:37:75:4B:1B:32:B8:0E:BA:E7:41:6D:B6
	//                     3D:05:F5:6A:99:39:72:0B:7C:8E:3D:CC:54:F6:A3:D1
	// https://crt.sh/?id=19602741 (crt.sh ID=19602741)
	"FAE46000D8F7042558541E98ACF351279589F83B6D3001C18442E4403D111849",

	// /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root G2
	// SHA256 Fingerprint: CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE
	//                     47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F
	// https://crt.sh/?id=8656329 (crt.sh ID=8656329)
	"8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26",

	// /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root G3
	// SHA256 Fingerprint: 31:AD:66:48:F8:10:41:38:C7:38:F3:9E:A4:32:01:33
	//                     39:3E:3A:18:CC:02:29:6E:F9:7C:2A:C9:EF:67:31:D0
	// https://crt.sh/?id=8568700 (crt.sh ID=8568700)
	"B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97",

	// /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Transition ECC Root
	// SHA256 Fingerprint: 45:BF:04:DC:A5:DE:7A:63:39:F1:DF:83:5B:C9:01:34
	//                     57:B4:87:FD:B4:30:8E:40:80:C6:42:3C:8E:4B:27:05
	// https://crt.sh/?id=281399768 (crt.sh ID=281399768)
	"7CAC9A0FF315387750BA8BAFDB1C2BC29B3F0BBA16362CA93A90F84DA2DF5F3E",

	// /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Transition RSA Root
	// SHA256 Fingerprint: E5:2B:44:CD:1E:6A:9A:DA:0A:04:09:D1:CC:5D:73:A6
	//                     F4:17:60:3D:70:E6:F5:DC:54:83:AB:8A:DA:EF:3C:A4
	// https://crt.sh/?id=281399766 (crt.sh ID=281399766)
	"AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE",
}

type result struct {
	IsDistrusted bool     `json:"isDistrusted"`
	Reasons      []string `json:"reasons"`
}

func (w runner) Run(in worker.Input, res chan worker.Result) {
	var (
		r       result
		reasons []string
	)
	paths, err := in.DBHandle.GetCertPaths(&in.Certificate)
	if err != nil {
		w.error(res, "failed to retrieve certificate paths: %v", err)
	}
	r.IsDistrusted, reasons = evalPaths(paths)
	r.Reasons = append(r.Reasons, reasons...)
	out, _ := json.Marshal(r)
	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     out,
	}
}

// evalPaths recursively processes certificate paths and checks each entity
// against the list of blacklisted symantec certs
func evalPaths(paths certificate.Paths) (distrust bool, reasons []string) {
	// assume distrust and change that if we find a trusted path
	distrust = true
	x509Cert, _ := paths.Cert.ToX509()
	spkihash := certificate.SPKISHA256(x509Cert)
	if evalBlacklist(spkihash) {
		reason := fmt.Sprintf("path uses a blacklisted cert: %s (id=%d)", paths.Cert.Subject.String(), paths.Cert.ID)
		if !alreadyPresent(reason, reasons) {
			reasons = append(reasons, reason)
		}
		return
	}
	if len(paths.Parents) == 0 {
		// if is not directly distrusted and doesn't have any parent, set distrust to false
		distrust = false
		return
	}
	for _, parent := range paths.Parents {
		theirDistrust, theirReasons := evalPaths(parent)
		for _, theirReason := range theirReasons {
			if !alreadyPresent(theirReason, reasons) {
				reasons = append(reasons, theirReason)
			}
		}
		if theirDistrust {
			// if the parent is distrusted, check if the current cert is whitelisted,
			// and if so, override the distrust decision
			if evalWhitelist(spkihash) {
				distrust = false
				reason := fmt.Sprintf("whitelisted intermediate %s (id=%d) override blacklisting of %d",
					paths.Cert.Subject.String(), paths.Cert.ID, parent.Cert.ID)
				if !alreadyPresent(reason, reasons) {
					reasons = append(reasons, reason)
				}
			}
		} else {
			// when the parent is a root that is not blacklisted, but it isn't trusted by mozilla,
			// then flag the chain as distrusted anyway
			if parent.Cert.CA && len(parent.Parents) == 0 && !parent.Cert.ValidationInfo["Mozilla"].IsValid {
				reason := fmt.Sprintf("path uses a root not trusted by Mozilla: %s (id=%d)",
					parent.Cert.Subject.String(), parent.Cert.ID)
				if !alreadyPresent(reason, reasons) {
					reasons = append(reasons, reason)
				}
			} else {
				distrust = false
			}
		}
	}
	return
}

// check if the SPKI hash of a cert is blacklisted
func evalBlacklist(spkihash string) bool {
	for _, blacklisted := range blacklist {
		if strings.ToUpper(spkihash) == strings.ToUpper(blacklisted) {
			return true
		}
	}
	return false
}

// check if the SPKI hash of a cert matches the ones in the whitelist.
// here we use the spki because CAs might create more certs from those whitelisted keys
func evalWhitelist(spkihash string) bool {
	for _, whitelisted := range whitelist {
		if strings.ToUpper(spkihash) == strings.ToUpper(whitelisted) {
			return true
		}
	}
	return false
}

func alreadyPresent(val string, slice []string) bool {
	for _, entry := range slice {
		if entry == val {
			return true
		}
	}
	return false
}

func (w runner) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
	}
}

func (w runner) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var (
		r          result
		addReasons bool
	)
	err = json.Unmarshal(input, &r)
	if err != nil {
		err = fmt.Errorf("Symantec distrust worker: failed to parse results: %v", err)
		return
	}
	if r.IsDistrusted {
		results = append(results, "* Symantec distrust: impacted")
		addReasons = true
	} else {
		if len(r.Reasons) > 0 {
			results = append(results, "* Symantec distrust: not impacted, but found paths with distrusted certs")
			addReasons = true
		} else {
			results = append(results, "* Symantec distrust: not impacted")
		}
	}
	if addReasons {
		for _, reason := range r.Reasons {
			results = append(results, fmt.Sprintf("  - %s", reason))
		}
		results = append(results, "  - for details, read https://wiki.mozilla.org/CA/Upcoming_Distrust_Actions")
	}
	return results, nil
}
