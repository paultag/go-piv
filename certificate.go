package piv

import (
	"crypto/x509"

	"pault.ag/go/othername"
	"pault.ag/go/othername/fasc"
)

type Certificate struct {
	*x509.Certificate

	CompletedNACI *bool

	PricipalNames []string
	FASCs         []fasc.FASC
}

func NewCertificate(cert *x509.Certificate) (*Certificate, error) {
	ret := Certificate{Certificate: cert}
	var err error

	ret.CompletedNACI = HasNACI(cert)

	ret.PricipalNames, err = othername.UPNs(cert)
	if err != nil {
		return nil, err
	}
	ret.FASCs, err = othername.FASCs(cert)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}
