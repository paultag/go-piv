package main

import (
	"fmt"
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
	fmt.Fprintf(w, "Certificate:\n")
	fmt.Fprintf(w, "  Subject: %s\n", cert.Subject.String())
	fmt.Fprintf(w, "  Issuer: %s\n", cert.Issuer.String())

	if len(cert.PrincipalNames) > 0 {
		fmt.Fprintf(w, "  UPNs:\n")
		for _, upn := range cert.PrincipalNames {
			fmt.Fprintf(w, "    %s\n", upn)
		}
	}

	if len(cert.FASCs) > 0 {
		fmt.Fprintf(w, "  FASC:\n")
		for _, fasc := range cert.FASCs {
			fmt.Fprintf(w, "    %s\n", fasc.String())
		}
	}

	err := pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	fmt.Fprintf(w, "\n")

	return err
}
