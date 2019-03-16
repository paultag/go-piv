package main

import (
	"fmt"
	"image/png"
	"io/ioutil"
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/cbeff/jpeg2000"
	"pault.ag/go/piv/biometrics"
	"pault.ag/go/piv/cmd/pivtk/internal"
)

func Facial(c *cli.Context) error {
	imageFormatString := "%s.facial.%d.png"
	asciiOut := c.Bool("ascii-out")
	imageOut := c.Bool("image-out")

	for _, path := range c.Args() {
		fd, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fd.Close()
		bytes, err := ioutil.ReadAll(fd)
		if err != nil {
			return err
		}

		cbeff, err := biometrics.ParseTLVCBEFF(bytes)
		if err != nil {
			return err
		}

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
		ohshit(err)

		for i, image := range facial.Images {
			img, err := jpeg2000.Parse(image.Data)
			if err != nil {
				return err
			}

			if asciiOut {
				if err := internal.PrintBraille(img); err != nil {
					return err
				}
			}

			if imageOut {
				fd, err := os.Create(fmt.Sprintf(imageFormatString, personId, i))
				ohshit(err)
				defer fd.Close()
				if err := png.Encode(fd, img); err != nil {
					return err
				}
			}
		}

		fd.Close()
	}
	return nil
}

var FacialCommand = cli.Command{
	Name:   "facial",
	Action: Facial,
	Usage:  "",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "image-out",
		},
		cli.BoolTFlag{
			Name: "ascii-out",
		},
	},
}
