package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

func init() {
	register("import-key", cmdImportKey, `
usage: tuf import-key [--expires=<days>] <role> <file>

Import an existing signing key for the given role.

The key will be imported from the file and added to the "keys" directory with
filename pattern "ROLE-KEYID.json". The root metadata file will also be staged
with the addition of the key's ID to the role's list of key IDs.

Options:
  --expires=<days>   Set the root metadata file to expire <days> days from now.
`)
}

func cmdImportKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	file := args.String["<file>"]
	var err error

	var privateKey data.PrivateKey
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &privateKey); err != nil {
		return fmt.Errorf("failed to unmarshal key file: %w", err)
	}

	signer, err := keys.GetSigner(&privateKey)
	if err != nil {
		return fmt.Errorf("failed to get signer for key file: %w", err)
	}

	if arg := args.String["--expires"]; arg != "" {
		var expires time.Time
		expires, err = parseExpires(arg)
		if err != nil {
			return err
		}
		err = repo.AddPrivateKeyWithExpires(role, signer, expires)
	} else {
		err = repo.AddPrivateKey(role, signer)
	}
	if err != nil {
		return fmt.Errorf("failed to add key to repository: %w", err)
	}

	keyids := signer.PublicData().IDs()
	for _, id := range keyids {
		fmt.Println("Imported", role, "key with ID", id)
	}
	return nil
}
