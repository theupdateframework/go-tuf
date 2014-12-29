package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("add", cmdAdd, `
usage: tuf add <path>

Add a target file.
`)
}

func cmdAdd(args *docopt.Args, repo *tuf.Repo) error {
	return repo.AddTarget(args.String["<path>"], nil)
}
