package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("revoke-key", cmdRevokeKey, `
usage: tuf revoke-key [--expires=<days>] <role> <id>

Revoke a signing key

The key will be removed from the root metadata file, but the key will remain in the
"keys" directory if present.

Options:
  --expires=<days>   Set the root metadata file to expire <days> days from now.
`)
}

func cmdRevokeKey(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.RevokeKeyWithExpires(args.String["<role>"], args.String["<id>"], expires)
	}
	return repo.RevokeKey(args.String["<role>"], args.String["<id>"])
}
