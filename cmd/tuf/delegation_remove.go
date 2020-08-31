package main

import (
	"errors"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("dele-remove", cmdDelegationRemove, `
usage: tuf dele-remove <name> [--expires=<days>] [--all] [<path>...]

Remove target file(s) from a delegated role

Options:
  --all              Remove all target files.
  --expires=<days>   Set the targets manifest to expire <days> days from now.
`)
}

func cmdDelegationRemove(args *docopt.Args, repo *tuf.Repo) error {
	paths := args.All["<path>"].([]string)
	if len(paths) == 0 && !args.Bool["--all"] {
		return errors.New("either specify some paths or set the --all flag to remove all targets")
	}
	argv := args.String["<name>"]
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.DelegateRemoveTargetsWithExpires(argv, paths, expires)
	}
	return repo.DelegateRemoveTargets(argv, paths)
}
