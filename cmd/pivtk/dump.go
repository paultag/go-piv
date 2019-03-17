package main

import (
	"fmt"
	"os"

	"github.com/chzyer/readline"
	"github.com/urfave/cli"

	// "pault.ag/go/piv"
	"pault.ag/go/piv/pkcs11"
)

func Dump(c *cli.Context) error {
	var pin *string = nil
	if c.Bool("login") {
		pinBytes, err := readline.Password("Enter PIN: ")
		if err != nil {
			return err
		}
		npin := string(pinBytes)
		pin = &npin
	}

	token, err := pkcs11.New(pkcs11.Config{
		Module: "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
		PIN:    pin,
	})
	if err != nil {
		return err
	}

	if err := OutputPEMFunc(token.AuthenticationCertificate, os.Stdout); err != nil {
		if err != pkcs11.NotFound {
			return err
		}
		fmt.Printf("No Certificate the Authentication slot\n")
	}

	if err := OutputPEMFunc(token.DigitalSignatureCertificate, os.Stdout); err != nil {
		if err != pkcs11.NotFound {
			return err
		}
		fmt.Printf("No Certificate the Digital Signature slot\n")
	}

	if err := OutputPEMFunc(token.CardAuthenticationCertificate, os.Stdout); err != nil {
		if err != pkcs11.NotFound {
			return err
		}
		fmt.Printf("No Certificate the Card Authentication slot\n")
	}

	cbeff, err := token.Facial()
	if err != nil {
		if err != pkcs11.NotFound {
			return err
		}
		fmt.Printf("Facial data not found\n")
	} else {
		if err := WriteFacialToDisk(cbeff); err != nil {
			return err
		}
	}

	return nil
}

var DumpCommand = cli.Command{
	Name:   "dump",
	Action: Dump,
	Usage:  "",
	Flags: []cli.Flag{
		cli.BoolFlag{Name: "login"},
	},
}
