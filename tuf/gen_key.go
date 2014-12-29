package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("gen-key", cmdGenKey, `
usage: tuf gen-key <role>

Generate a new signing key for the given role.

The key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root manifest will also be staged
with the addition of the key's ID to the role's list of key IDs.
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	return repo.GenKey(args.String["<role>"])
}
