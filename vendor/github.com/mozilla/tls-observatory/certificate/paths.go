package certificate

import "fmt"

// Paths represent the chain of trust between a given certificate
// and one of multiple parents. It is meant to be walked recursively
// from an end-entity to a trusted root
type Paths struct {
	Cert    *Certificate `json:"certificate"`
	Parents []Paths      `json:"parents"`
	// vars to help pretty printing
	sep       string
	depth     int
	neighbors int
	islast    bool
}

const (
	E_SEP string = "   "
	S_SEP string = "│  "
	T_SEP string = "├──"
	L_SEP string = "└──"
	C_SEP string = "───"
)

func (p Paths) String() (str string) {
	var sep, nsep string
	for i := 0; i < p.depth; i++ {
		if i == p.depth-1 {
			if p.islast || p.neighbors == 0 {
				sep += L_SEP
				nsep += E_SEP
			} else {
				sep += T_SEP
				nsep += S_SEP
			}
		} else if i == 0 {
			nsep += p.sep

		}
	}
	sep = p.sep + sep
	str = fmt.Sprintf("%s%s (id=%d)\n", sep, p.Cert.Subject.String(), p.Cert.ID)
	for i, parent := range p.Parents {
		parent.sep = nsep
		parent.neighbors = len(p.Parents)
		parent.depth = p.depth + 1
		if i == len(p.Parents)-1 {
			parent.islast = true
		}
		str += parent.String()
	}
	return
}

func (p Paths) GetValidityMap() map[string]ValidationInfo {
	return GetValidityMap(
		p.IsTrustedBy(Ubuntu_TS_name),
		p.IsTrustedBy(Mozilla_TS_name),
		p.IsTrustedBy(Microsoft_TS_name),
		p.IsTrustedBy(Apple_TS_name),
		p.IsTrustedBy(Android_TS_name))
}

func (p Paths) IsTrustedBy(truststore string) bool {
	// if the current cert is known to be trusted, return now
	if _, ok := p.Cert.ValidationInfo[truststore]; ok {
		if p.Cert.ValidationInfo[truststore].IsValid {
			return true
		}
	}
	// otherwise try to go further down the path to find a trusted cert
	for _, parent := range p.Parents {
		if parent.IsTrustedBy(truststore) {
			return true
		}
	}
	return false
}
