package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func delegationDelete() {
	register("delegateDelete", cmdDelegationDelete, `
usage: tuf dele-delete [--role-name=<data>]

Delete an existing non-top target role.

This can be used to remove a target role, only when a
that non-top target role has already been initialized. An role name
is required.
  `)
}

func cmdDelegationDelete(args *docopt.Args, repo *tuf.Repo) error {
	if c := args.String["--role-name"]; c != "" {
		return repo.RemoveDeleRole(c)
	}
	return nil
}
