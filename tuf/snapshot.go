package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("snapshot", cmdSnapshot, `
usage: tuf snapshot [--compression=<format>]

Update the snapshot manifest.
`)
}

func cmdSnapshot(args *docopt.Args, repo *tuf.Repo) error {
	// TODO: parse --compression
	return repo.Snapshot(tuf.CompressionTypeNone)
}
