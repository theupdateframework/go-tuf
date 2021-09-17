package main

import (
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("clean", cmdClean, `
usage: tuf clean

Remove all staged metadata files.
`)
}

func cmdClean(args *docopt.Args, repo *tuf.Repo) error {
	err := repo.Clean()
	if err == tuf.ErrNewRepository {
		fmt.Fprintln(os.Stderr, "tuf: refusing to clean new repository")
		return nil
	}
	return err
}
