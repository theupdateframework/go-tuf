package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	tuf "github.com/theupdateframework/go-tuf"
)

func init() {
	register("sign-payload", cmdSignPayload, `
usage: tuf sign-payload --role=<role> <path>

Sign a file (outside of the TUF repo) using keys for the given role (from the TUF repo).

Typically, path will be the output of "tuf payload".
`)
}

func cmdSignPayload(args *docopt.Args, repo *tuf.Repo) error {
	payload, err := os.ReadFile(args.String["<path>"])
	if err != nil {
		return err
	}

	signatures, err := repo.SignRaw(args.String["--role"], payload)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "tuf: signed")

	bytes, err := json.Marshal(signatures)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(bytes))

	return nil
}
