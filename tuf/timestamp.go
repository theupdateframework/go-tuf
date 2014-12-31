package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("timestamp", cmdTimestamp, `
usage: tuf timestamp

Update the timestamp manifest.
`)
}

func cmdTimestamp(args *docopt.Args, repo *tuf.Repo) error {
	return repo.Timestamp()
}
