package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("restore", cmdRestore, `
usage: tuf restore

Restore all registration of delegated role from database. 
Only used when current repository is not used anymore.

Options:
  --expires=<days>   Set the targets manifest to expire <days> days from now.
  --custom=<data>    Set custom JSON data for the target(s).
`)
}
func cmdRestore(args *docopt.Args, repo *tuf.Repo) error {
	repo.RestoreAll()
	return nil
}
