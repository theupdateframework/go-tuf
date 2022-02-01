package main

import (
	"fmt"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("payload", cmdPayload, `
usage: tuf payload <role>

Output a role's metadata in a ready-to-sign format.

The output is canonicalized.
`)
}

func cmdPayload(args *docopt.Args, repo *tuf.Repo) error {
	p, err := repo.Payload(args.String["<role>"])
	if err != nil {
		return err
	}
	fmt.Print(string(p))
	return nil
}
