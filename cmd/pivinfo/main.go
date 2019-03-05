package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"pault.ag/go/piv"
)

func main() {
	for _, el := range os.Args[1:] {
		fd, err := os.Open(el)
		if err != nil {
			panic(err)
		}
		defer fd.Close()
		bytes, err := ioutil.ReadAll(fd)
		if err != nil {
			panic(err)
		}
		block, _ := pem.Decode(bytes)
		_ = block
		cert, err := x509.ParseCertificate(bytes)
		if err != nil {
			log.Println(err)
			continue
		}

		pcert, err := piv.NewCertificate(cert)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Serial: %x\n", cert.SerialNumber)
		fmt.Printf(" CN: %s\n", cert.Subject.CommonName)

		for _, name := range pcert.FASCs {
			fmt.Printf(" FASC: %s\n", name)
		}

		for _, name := range pcert.PrincipalNames {
			fmt.Printf(" UPN: %s\n", name)
		}

		for _, email := range cert.EmailAddresses {
			fmt.Printf(" Email: %s\n", email)
		}

		fmt.Printf("\n")
		fd.Close()
	}
}
