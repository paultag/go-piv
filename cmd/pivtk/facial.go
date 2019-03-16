package main

import (
	"fmt"
	"image/png"
	"io/ioutil"
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/cbeff/jpeg2000"
	"pault.ag/go/piv/biometrics"
)

func Facial(c *cli.Context) error {
	imageFormatString := c.String("image-output")

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

		facial, err := cbeff.Facial()
		ohshit(err)

		for i, image := range facial.Images {
			img, err := jpeg2000.Parse(image.Data)
			if err != nil {
				return err
			}

			fd, err := os.Create(fmt.Sprintf(imageFormatString, i))
			ohshit(err)
			defer fd.Close()
			if err := png.Encode(fd, img); err != nil {
				fd.Close()
				ohshit(err)
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
		cli.StringFlag{
			Name:  "image-output",
			Value: "facial.%d.png",
			Usage: "",
		},
	},
}
