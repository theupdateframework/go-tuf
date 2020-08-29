package main

import (
	"encoding/json"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("dele-add", cmdDelegateAdd, `
usage: tuf dele-add <names> [--expires=<days>] [--custom=<data>] [<path>...]

Add target file(s) for a non-top target role, a name must be provided.

Options:
  --expires=<days>   Set the targets manifest to expire <days> days from now.
  --custom=<data>    Set custom JSON data for the target(s).
`)
}
func cmdDelegateAdd(args *docopt.Args, repo *tuf.Repo) error {
	var custom json.RawMessage
	if c := args.String["--custom"]; c != "" {
		custom = json.RawMessage(c)
	}
	paths := args.All["<path>"].([]string)
	argv := args.String["<names>"]
	if arg := args.String["--expires"]; arg != "" {
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		return repo.DelegateAddTargetsWithExpires(argv, paths, custom, expires)
	}
	return repo.DelegateAddTargets(argv, paths, custom)
}
