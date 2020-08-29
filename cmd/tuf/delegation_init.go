package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func delegationInit() {
	register("dele-init", cmdDeleInit, `
usage: tuf dele-init [--role-name=<data>]

Initialize a new non-top target role.

This can be used to initialize a new target role, only when a
top-level target role has already been initialized. An role name
is required.
  `)
}

func cmdDeleInit(args *docopt.Args, repo *tuf.Repo) error {
	if c := args.String["--role-name"]; c != "" {
		repo.DelegateInit(c)
	}
	return nil
}
