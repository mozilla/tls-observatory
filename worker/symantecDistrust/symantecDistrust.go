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
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

type runner struct {
}

var blacklist = []distrustedCert{
	{
		Name:   "/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA",
		SHA256: "FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A",
	},
	{
		Name:   "/C=US/O=GeoTrust Inc./OU=(c) 2007 GeoTrust Inc. - For authorized use only/CN=GeoTrust Primary Certification Authority - G2",
		SHA256: "5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766",
	},
	{
		Name:   "/C=US/O=GeoTrust Inc./OU=(c) 2008 GeoTrust Inc. - For authorized use only/CN=GeoTrust Primary Certification Authority - G3",
		SHA256: "B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4",
	},
	{
		Name:   "/C=US/O=GeoTrust Inc./CN=GeoTrust Primary Certification Authority",
		SHA256: "37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C",
	},
	{
		Name:   "/C=US/O=GeoTrust Inc./CN=GeoTrust Universal CA",
		SHA256: "A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912",
	},
	{
		Name:   "/C=US/O=GeoTrust Inc./CN=GeoTrust Universal CA 2",
		SHA256: "A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B",
	},
	{
		Name:   "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 1 Public Primary Certification Authority - G4",
		SHA256: "363F3C849EAB03B0A2A0F636D7B86D04D3AC7FCFE26A0A9121AB9795F6E176DF",
	},
	{
		Name:   "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 1 Public Primary Certification Authority - G6",
		SHA256: "9D190B2E314566685BE8A889E27AA8C7D7AE1D8AADDBA3C1ECF9D24863CD34B9",
	},
	{
		Name:   "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 2 Public Primary Certification Authority - G4",
		SHA256: "FE863D0822FE7A2353FA484D5924E875656D3DC9FB58771F6F616F9D571BC592",
	},
	{
		Name:   "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 2 Public Primary Certification Authority - G6",
		SHA256: "CB627D18B58AD56DDE331A30456BC65C601A4E9B18DEDCEA08E7DAAA07815FF0",
	},
	{
		Name:   "/C=US/O=thawte, Inc./OU=Certification Services Division/OU=(c) 2006 thawte, Inc. - For authorized use only/CN=thawte Primary Root CA",
		SHA256: "8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F",
	},
	{
		Name:   "/C=US/O=thawte, Inc./OU=(c) 2007 thawte, Inc. - For authorized use only/CN=thawte Primary Root CA - G2",
		SHA256: "A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557",
	},
	{
		Name:   "/C=US/O=thawte, Inc./OU=Certification Services Division/OU=(c) 2008 thawte, Inc. - For authorized use only/CN=thawte Primary Root CA - G3",
		SHA256: "4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 1 Public Primary Certification Authority - G3",
		SHA256: "CBB5AF185E942A2402F9EACBC0ED5BB876EEA3C1223623D00447E4F3BA554B65",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 2 Public Primary Certification Authority - G3",
		SHA256: "92A9D9833FE1944DB366E8BFAE7A95B6480C2D6C6C2A1BE65D4236B608FCA1BB",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 1999 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G3",
		SHA256: "EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2007 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G4",
		SHA256: "69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5",
		SHA256: "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF",
	},
	{
		Name:   "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2008 VeriSign, Inc. - For authorized use only/CN=VeriSign Universal Root Certification Authority",
		SHA256: "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C",
	},
}

type distrustedCert struct {
	Name   string
	SHA256 string
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
	if evalBlacklist(paths.Cert.Hashes.SHA256) {
		reasons = append(reasons, fmt.Sprintf("path uses a blacklisted cert: %s (id=%d)", paths.Cert.Subject.String(), paths.Cert.ID))
		return
	}
	if len(paths.Parents) == 0 {
		// if is not directly distrusted and doesn't have any parent, set distrust to false
		distrust = false
		return
	}
	for _, parent := range paths.Parents {
		theirDistrust, theirReasons := evalPaths(parent)
		reasons = append(reasons, theirReasons...)
		if !theirDistrust {
			// if we find a parent that's not ditrusted, make sure it's in the Firefox
			// truststore, and if so, it's a valid path, and distrust should be false
			if parent.Cert.CA && len(parent.Parents) == 0 && parent.Cert.ValidationInfo["mozilla"].IsValid {
				distrust = false
			} else {
				reasons = append(reasons, fmt.Sprintf("path uses a root not trusted by Mozilla: %s (id=%d)", parent.Cert.Subject.String(), parent.Cert.ID))
			}
		}
	}
	return
}

func evalBlacklist(hash string) bool {
	for _, item := range blacklist {
		if strings.ToUpper(hash) == strings.ToUpper(item.SHA256) {
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
