package main

import (
	"fmt"
	"os"

	"github.com/DataDog/go-tuf"
	"github.com/flynn/go-docopt"
)

func init() {
	register("payload", cmdPayload, `
usage: tuf payload <metadata>

Outputs the metadata file for a role in a ready-to-sign (canonicalized) format.
`)
}

func cmdPayload(args *docopt.Args, repo *tuf.Repo) error {
	p, err := repo.Payload(args.String["<metadata>"])
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(p))
	return nil
}
