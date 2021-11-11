package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("root-keys", cmdRootKeys, `
usage: tuf root-keys

Outputs a JSON serialized array of root keys to STDOUT.

The resulting JSON should be distributed to clients for performing initial updates.
`)
}

func cmdRootKeys(args *docopt.Args, repo *tuf.Repo) error {
	keys, err := repo.RootKeys()
	if err != nil {
		return err
	}
	data, err := json.Marshal(keys)
	if err == nil {
		fmt.Fprintf(os.Stderr, "The resulting JSON should be distributed to clients for performing initial updates:\n\n")
		fmt.Fprintln(os.Stdout, string(data))
	}
	return err
}
