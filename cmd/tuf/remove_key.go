package main

import (
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf"
	"github.com/flynn/go-docopt"
)

func init() {
	register("remove-key", cmdRemoveKey, `
usage: tuf remove-key [--expires=<days>] <role> <id>

Remove a signing key

Before the key is removed the key will be first revoked
The key will then be removed from the root metadata file and if the key is present in 
"keys" directory it will also be removed
`)
}

func cmdRemoveKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<roles>"]
	keyID := args.String["<id>"]
	if err := repo.RevokeKey(role, keyID); err != nil {
		return err
	}
	keyPath := filepath.Join("keys", keyID)
	if _, err := os.Stat(keyPath); err == nil {
		if err := os.Remove(keyPath); err != nil {
			return err
		}
	}
	return nil
}