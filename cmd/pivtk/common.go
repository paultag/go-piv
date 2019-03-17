package main

import (
	"fmt"
	"image/png"
	"io"
	"os"

	"encoding/pem"

	"pault.ag/go/cbeff"
	"pault.ag/go/cbeff/jpeg2000"
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

func WriteFacialToDisk(cbeff *cbeff.CBEFF) error {
	imageFormatString := "%s.facial.%d.png"

	fasc, err := cbeff.Header.ParseFASC()
	if err != nil {
		return err
	}

	personId := fmt.Sprintf(
		"%d%d%d",
		fasc.OrganizationIdentifier,
		fasc.PersonIdentifier,
		fasc.PersonAssociation,
	)

	facial, err := cbeff.Facial()
	if err != nil {
		return err
	}

	for i, image := range facial.Images {
		img, err := jpeg2000.Parse(image.Data)
		if err != nil {
			return err
		}

		fd, err := os.Create(fmt.Sprintf(imageFormatString, personId, i))
		if err != nil {
			return err
		}

		defer fd.Close()
		if err := png.Encode(fd, img); err != nil {
			return err
		}
		fd.Close()
	}

	return nil
}
