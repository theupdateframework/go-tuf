package main

import (
	"encoding/json"
	"os"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("target-keys", cmdTargKeys, `
usage: tuf target-keys

Outputs a JSON serialized array of targets keys to STDOUT.

The resulting JSON should be distributed to clients for performing initial updates.
`)
}

func cmdTargKeys(args *docopt.Args, repo *tuf.Repo) error {
	keys, err := repo.RootKeys()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(keys)
}
