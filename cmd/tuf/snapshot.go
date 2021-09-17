package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("snapshot", cmdSnapshot, `
usage: tuf snapshot [--expires=<days>]

Update the snapshot metadata file.

Alternatively, passphrases can be set via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE

Options:
  --expires=<days>   Set the snapshot metadata file to expire <days> days from now.
`)
}

func cmdSnapshot(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.SnapshotWithExpires(expires)
	}
	return repo.Snapshot()
}
