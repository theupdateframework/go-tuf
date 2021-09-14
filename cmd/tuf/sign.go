package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("sign", cmdSign, `
usage: tuf sign <manifest>

Sign a role's manifest.

Signs the given role's staged manifest with all keys present in the 'keys'
directory for that role.
`)
}

func cmdSign(args *docopt.Args, repo *tuf.Repo) error {
	return repo.Sign(args.String["<manifest>"])
}
