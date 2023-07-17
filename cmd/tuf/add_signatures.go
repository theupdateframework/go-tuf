package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DataDog/go-tuf"
	"github.com/DataDog/go-tuf/data"
	"github.com/flynn/go-docopt"
)

func init() {
	register("add-signatures", cmdAddSignature, `
usage: tuf add-signatures --signatures <sig_file> <metadata>

Adds signatures (the output of "sign-payload") to the given role metadata file.

If the signature does not verify, it will not be added.
`)
}

func cmdAddSignature(args *docopt.Args, repo *tuf.Repo) error {
	roleFilename := args.String["<metadata>"]

	f := args.String["<sig_file>"]
	sigBytes, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	sigs := []data.Signature{}
	if err = json.Unmarshal(sigBytes, &sigs); err != nil {
		return err
	}
	for _, sig := range sigs {
		if err = repo.AddOrUpdateSignature(roleFilename, sig); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "tuf: added", len(sigs), "new signature(s)")
	return nil
}
