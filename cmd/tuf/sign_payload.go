package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	tuf "github.com/theupdateframework/go-tuf"
	tufdata "github.com/theupdateframework/go-tuf/data"
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
	signed := tufdata.Signed{Signed: payload, Signatures: make([]tufdata.Signature, 0)}

	numKeys, err := repo.SignPayload(args.String["--role"], &signed)
	if err != nil {
		return err
	}

	bytes, err := json.Marshal(signed.Signatures)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(bytes))

	fmt.Fprintln(os.Stderr, "tuf: signed with", numKeys, "key(s)")
	return nil
}
