package main

import (
	"github.com/DataDog/go-tuf"
	"github.com/flynn/go-docopt"
)

func init() {
	register("sign", cmdSign, `
usage: tuf sign <metadata>

Sign a role's metadata file.

Signs the given role's staged metadata file with all keys present in the 'keys'
directory for that role.
`)
}

func cmdSign(args *docopt.Args, repo *tuf.Repo) error {
	return repo.Sign(args.String["<metadata>"])
}
