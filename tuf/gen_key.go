package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("gen-key", cmdGenKey, `
usage: tuf gen-key [--expires=<days>] <role>

Generate a new signing key for the given role.

The key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root manifest will also be staged
with the addition of the key's ID to the role's list of key IDs.

Options:
  --expires=<days>   Set the root manifest to expire <days> days from now.
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.GenKeyWithExpires(args.String["<role>"], expires)
	}
	return repo.GenKey(args.String["<role>"])
}
