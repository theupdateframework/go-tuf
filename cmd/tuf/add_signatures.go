package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	register("add-signatures", cmdAddSignature, `
usage: tuf add-signatures --signatures=<sig_file> [--format=<format>] [--key-id=<key-id>] <metadata>

Adds signatures (the output of "sign-payload") to the given role metadata file.

If the signature does not verify, it will not be added.

Options:
  --signatures=<sig_file>  the path to the file containing the signature(s)
  --format=<format>    One of 'json', 'hex', or 'base64'. Defaults to 'json'
  --key-id=<key-id>    The key-id of the signature being added. Only required if the format is not 'json'
`)
}

func cmdAddSignature(args *docopt.Args, repo *tuf.Repo) error {
	roleFilename := args.String["<metadata>"]

	f := args.String["--signatures"]
	sigBytes, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	sigs := []data.Signature{}
	switch args.String["--format"] {
	case "base64":
		base64bytes, err := base64.StdEncoding.DecodeString(string(sigBytes))
		if err != nil {
			return err
		}
		sigs = append(sigs, data.Signature{KeyID: args.String["--key-id"], Signature: base64bytes})
	case "hex":
		hex := data.HexBytes{}
		if err = hex.FromString(sigBytes); err != nil {
			return err
		}
		sigs = append(sigs, data.Signature{KeyID: args.String["--key-id"], Signature: hex})
	case "json":
	default:
		if err = json.Unmarshal(sigBytes, &sigs); err != nil {
			return err
		}
	}
	for _, sig := range sigs {
		if err = repo.AddOrUpdateSignature(roleFilename, sig); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "tuf: added", len(sigs), "new signature(s)")
	return nil
}
