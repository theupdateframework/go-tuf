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
	register("gen-key", cmdGenKey, `
usage: tuf gen-key [--expires=<days>] [--scheme=<scheme>] <role>

Generate a new signing key for the given role.

The key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root metadata file will also be staged
with the addition of the key's ID to the role's list of key IDs.

Alternatively, passphrases can be set via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE

Options:
  --expires=<days>   Set the root metadata file to expire <days> days from now.
  --scheme=<scheme>      Set the key scheme to use [default: ed25519].
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var keyids []string

	keyScheme := data.KeySchemeEd25519
	switch t := args.String["--scheme"]; t {
	case string(data.KeySchemeEd25519),
		string(data.KeySchemeECDSA_SHA2_P256),
		string(data.KeySchemeRSASSA_PSS_SHA256):
		keyScheme = data.KeyScheme(t)
	default:
		fmt.Fprint(os.Stderr, "Using default key scheme", keyScheme)
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
	keyids, err = repo.GenKeyWithSchemeAndExpires(role, expires, keyScheme)
	if err != nil {
		return err
	}
	for _, id := range keyids {
		fmt.Fprintf(os.Stdout, "Generated %s %s key with ID %s", role, keyScheme, id)
	}
	return nil
}
