package certificate

// Paths represent the chain of trust between a given certificate
// and one of multiple parents. It is meant to be walked recursively
// from an end-entity to a trusted root
type Paths struct {
	Cert    *Certificate
	Parents []Paths
	sep     string
}

func (p Paths) String() (str string) {
	if len(p.Parents) == 0 {
		str = p.sep + "`> root: "
	} else if p.sep != "" {
		str = p.sep + "`> intermediate: "
	}
	str += p.Cert.Subject.String()
	for _, parent := range p.Parents {
		parent.sep = p.sep + "   "
		str += "\n" + parent.String()
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
