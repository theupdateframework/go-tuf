package main

import (
	"github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/Godeps/_workspace/src/github.com/flynn/go-docopt"
)

func init() {
	register("add", cmdAdd, `
usage: tuf add [--expires=<days>] [<path>...]

Add target file(s).

Options:
  --expires=<days>   Set the targets manifest to expire <days> days from now.
`)
}

func cmdAdd(args *docopt.Args, repo *tuf.Repo) error {
	paths := args.All["<path>"].([]string)
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.AddTargetsWithExpires(paths, nil, expires)
	}
	return repo.AddTargets(paths, nil)
}
