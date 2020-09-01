package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("dele-revoke", cmdDeleRevokeKey, `
usage: tuf dele-revoke [--expires=<days>] <role> <id>

Revoke a signing key for delegated role

The key will be removed from the top-target manifest, but the key will remain in the
"keys" directory if present.

Options:
  --expires=<days>   Set the root manifest to expire <days> days from now.
`)
}

func cmdDeleRevokeKey(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.DelegateRevokeKeyWithExpires(args.String["<role>"], args.String["<id>"], expires)
	}
	return repo.DelegateRevokeKey(args.String["<role>"], args.String["<id>"])
}
