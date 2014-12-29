package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("remove", cmdRemove, `
usage: tuf remove <path>

Remove a target file.
`)
}

func cmdRemove(args *docopt.Args, repo *tuf.Repo) error {
	return repo.RemoveTarget(args.String["<path>"])
}
