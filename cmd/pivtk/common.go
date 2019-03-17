package main

import (
	"io"

	"encoding/pem"

	"pault.ag/go/piv"
)

func OutputPEMFunc(cf func() (*piv.Certificate, error), w io.Writer) error {
	cert, err := cf()
	if err != nil {
		return err
	}
	return OutputPEM(cert, w)
}

func OutputPEM(cert *piv.Certificate, w io.Writer) error {
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
