package main

import (
	"os"

	"github.com/urfave/cli"
)

func ohshit(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "pivtk"
	app.Usage = ""
	app.Version = "0.1"

	app.Flags = []cli.Flag{}

	app.Commands = []cli.Command{
		FacialCommand,
		DumpCommand,
	}

	ohshit(app.Run(os.Args))
}
