package main

import (
	"github.com/flynn/go-docopt"
	"github.com/flynn/go-tuf"
)

func init() {
	register("add", cmdAdd, `
usage: tuf add [--expires=<days>] <path>

Add a target file.

Options:
  --expires=<days>   Set the targets manifest to expire <days> days from now.
`)
}

func cmdAdd(args *docopt.Args, repo *tuf.Repo) error {
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.AddTargetWithExpires(args.String["<path>"], nil, expires)
	}
	return repo.AddTarget(args.String["<path>"], nil)
}
