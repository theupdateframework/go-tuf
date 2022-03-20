package main

import (
	"fmt"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("payload", cmdPayload, `
usage: tuf payload <metadata>

Output the metadata file for a role in a ready-to-sign format.

The output is canonicalized.
`)
}

func cmdPayload(args *docopt.Args, repo *tuf.Repo) error {
	p, err := repo.Payload(args.String["<metadata>"])
	if err != nil {
		return err
	}
	fmt.Print(string(p))
	return nil
}
