package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	register("gen-key", cmdGenKey, `
usage: tuf gen-key [--expires=<days>] [--type=<type>] <role>

Generate a new signing key for the given role.

The key will be serialized to JSON and written to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root metadata file will also be staged
with the addition of the key's ID to the role's list of key IDs.

Alternatively, passphrases can be set via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE

Options:
  --expires=<days>   Set the root metadata file to expire <days> days from now.
  --type=<type>      Set the type of key to generate [default: ed25519].
`)
}

func cmdGenKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	var keyids []string

	var keyType data.KeyType
	switch t := args.String["--type"]; t {
	case string(data.KeyTypeEd25519),
		string(data.KeyTypeECDSA_SHA2_P256),
		string(data.KeyTypeRSASSA_PSS_SHA256):
		keyType = data.KeyType(t)
	default:
		return errors.New("invalid key type")
	}

	var expires time.Time
	if arg := args.String["--expires"]; arg != "" {
		exp, err := parseExpires(arg)
		if err != nil {
			return err
		}
		expires = exp
	} else {
		expires = data.DefaultExpires(role)
	}
	keyids, err := repo.GenKeyWithTypeAndExpires(role, expires, data.KeyType(keyType))
	if err != nil {
		return err
	}
	for _, id := range keyids {
		fmt.Println("Generated", role, "key with ID", id)
	}
	return nil
}
