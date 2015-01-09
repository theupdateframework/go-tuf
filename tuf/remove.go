package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("remove", cmdRemove, `
usage: tuf remove [--expires=<days>] <path>

Remove a target file.

Options:
  --expires=<days>   Set the targets manifest to expire <days> days from now.
`)
}

func cmdRemove(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.RemoveTargetWithExpires(args.String["<path>"], expires)
	}
	return repo.RemoveTarget(args.String["<path>"])
}
