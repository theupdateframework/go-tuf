package main

import (
	"io"
	"os"

	"github.com/flynn/go-docopt"
	tuf "github.com/theupdateframework/go-tuf/client"
)

func init() {
	register("init", cmdInit, `
usage: tuf-client init [-s|--store=<path>] <url> [<root-metadata-file>]

Options:
  -s <path>    The path to the local file store [default: tuf.db]

Initialize the local file store with root metadata.
  `)
}

func cmdInit(args *docopt.Args, client *tuf.Client) error {
	file := args.String["<root-metadata-file>"]
	var in io.Reader
	if file == "" || file == "-" {
		in = os.Stdin
	} else {
		var err error
		in, err = os.Open(file)
		if err != nil {
			return err
		}
	}
	bytes, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	return client.Init(bytes)
}
