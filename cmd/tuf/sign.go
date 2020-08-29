package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("sign", cmdSign, `
usage: tuf sign <manifest>

Sign a manifest. Note that manifest is in format of "role.json"
`)
}

func cmdSign(args *docopt.Args, repo *tuf.Repo) error {
	return repo.Sign(args.String["<manifest>"])
}
