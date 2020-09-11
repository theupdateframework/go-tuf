package main

import (
	"fmt"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("list", cmdList, `
usage: tuf list

List metadata in r.meta
`)
}

func cmdList(args *docopt.Args, repo *tuf.Repo) error {
	fmt.Println(repo.ListMeta())
	return nil
}
