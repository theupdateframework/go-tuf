package main

import (
	"fmt"
	"os"
	"time"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	register("add-key", cmdAddKey, `
usage: tuf add-key [--scheme=<scheme>] [--expires=<days>] [--public-key=<path>] <role>

Adds a new signing key for the given role.

The root metadata file will be staged
with the addition of the key's ID to the role's list of key IDs.

Options:
  --public-key=<path>    The Path to the file containing value of the public key. If absent, will be read from stdin.
  --expires=<days>    Set the metadata file to expire <days> days from now.
  --scheme=<scheme>      Set the key scheme to use [default: ed25519].
`)
}

func cmdAddKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var keyids []string

	var keyScheme data.KeyScheme
	switch t := args.String["--scheme"]; t {
	case string(data.KeySchemeEd25519),
		string(data.KeySchemeECDSA_SHA2_P256),
		string(data.KeySchemeRSASSA_PSS_SHA256):
		keyScheme = data.KeyScheme(t)
	default:
		fmt.Fprintf(os.Stderr, "tuf: key schema %s not recognised\n", t)
		return nil
	}
	f := args.String["--public-key"]
	var publicValue string
	if f != "" {
		bytes, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		publicValue = string(bytes)
	} else {
		var input string
		_, err := fmt.Scan(&input)
		if err != nil {
			return err
		}
		publicValue = input
	}
	var err error
	var expires time.Time
	if arg := args.String["--expires"]; arg != "" {
		expires, err = parseExpires(arg)
		if err != nil {
			return err
		}
	} else {
		expires = data.DefaultExpires(role)
	}
	keyids, err = repo.AddKeyWithSchemeAndExpires(role, expires, keyScheme, publicValue)
	if err != nil {
		return err
	}
	for _, id := range keyids {
		fmt.Fprintf(os.Stdout, "Add key with ID %s\n", id)
	}
	return nil
}
